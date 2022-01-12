(ns com.yetanalytics.pedestal-oidc.interceptor
  (:require [clojure.spec.alpha :as s]
            [no.nsd.clj-jwt :as clj-jwt]
            [io.pedestal.interceptor :as i]
            [io.pedestal.log :as log]
            [com.yetanalytics.pedestal-oidc.response :as resp]
            [com.yetanalytics.pedestal-oidc.config :as config]
            [com.yetanalytics.pedestal-oidc.request
             :as req]
            [com.yetanalytics.pedestal-oidc.request.authentication
             :as auth-req]
            [com.yetanalytics.pedestal-oidc.util :as util]
            [com.yetanalytics.pedestal-oidc.session :as session]
            [org.httpkit.client :as client]
            [cheshire.core :as json]
            [clojure.java.io :as io]
            [camel-snake-kebab.core :as csk]
            [clojure.tools.logging :as ctl]
            [clojure.pprint :as pp]))

;; TODO: maybe async
(defn- http!
  [request]
  (let [{:keys [status
                body]
         :as resp} @(client/request (merge request
                                           {:as :stream}))]
    (if (= 200 status)
      (with-open [rdr (io/reader body)]
        (json/parse-stream-strict rdr csk/->kebab-case-keyword))
      (throw (ex-info "Non-200 http status"
                      {:type ::oidc-http-error
                       :request request
                       :response resp
                       :body (slurp body)})))))

(defn default-unauthorized [ctx & [?ex & _]]
  (assoc ctx :response resp/unauthorized))

(s/def ::unauthorized fn?)

;; After https://github.com/propan/geheimtur/blob/master/src/geheimtur/impl/oauth2.clj#L24
(s/fdef login-redirect-interceptor
  :args (s/cat
         :config config/config-spec
         :callback-uri string?
         :kwargs (s/keys* :opt-un [::unauthorized])))

(defn login-redirect-interceptor
  "Return an interceptor that, based on a provider's config, will redirect to
  OIDC login. An unknown provider will result in a 400"
  [{:keys [providers]}
   callback-uri
   & {:keys [unauthorized]
      :or {unauthorized default-unauthorized}}]
  (i/interceptor
   {:enter
    (fn [{{{:keys [return]
            provider-name :provider
            :or {provider-name "default"
                 return "/"}} :query-params} :request
          :as ctx}]
      (try
        (if-let [provider (get providers (keyword provider-name))]
          (let [{:keys [authorization-endpoint]} (config/get-remote provider)
                state (util/generate-state)
                nonce (util/generate-nonce)
                auth-url (auth-req/build-url
                          provider
                          authorization-endpoint
                          callback-uri
                          state
                          nonce)]
            (assoc ctx
                   :response
                   (merge
                    (resp/redirect auth-url)
                    {:session
                     (session/new-session
                      nonce provider-name state return)})))
          (unauthorized ctx))
        (catch Exception ex
          (unauthorized ctx ex))))}))

(s/fdef login-callback-interceptor
  :args (s/cat
         :config config/config-spec
         :callback-uri string?
         :kwargs (s/keys* :opt-un [::unauthorized])))

(defn login-callback-interceptor
  "Given a config, return an interceptor that will handle OIDC login callbacks
  and redirect the user to the appropriate destination or 401"
  [{:keys [providers]}
   callback-uri
   & {:keys [unauthorized]
      :or {unauthorized default-unauthorized}}]
  (i/interceptor
   {:enter
    (fn [{{{:keys [state code]
            :as query-params} :query-params
           {{:keys [return]
             cb-provider :provider
             cb-state :state
             :as callback-data} :com.yetanalytics.pedestal-oidc/callback}
           :session} :request
          :keys [url-for]
          :as ctx}]
      (try
        (cond
          (nil? callback-data)
          (do
            (ctl/warn "OIDC callback data not found in session.")
            (unauthorized ctx))

          (not= state cb-state)
          (do (ctl/warn "OIDC callback state mismatch")
              (unauthorized ctx))
          :else
          (if-let [provider (get providers (keyword cb-provider))]
            ;; TODO: Get token, get user, add to context and then redirect to return
            (let [{:keys [token-endpoint
                          userinfo-endpoint]} (config/get-remote provider)
                  {:keys [access-token
                          refresh-token
                          expires-in
                          id-token] :as tokens} (http! (req/token-request
                                                        provider
                                                        token-endpoint
                                                        code
                                                        callback-uri))
                  ;; TODO: validate id-token, nonce
                  userinfo (http! (req/userinfo-request
                                   userinfo-endpoint
                                   access-token))]
              (assoc ctx
                     :response
                     (merge
                      (resp/redirect return)
                      {:session
                       (session/identified-session
                        tokens
                        userinfo)})))
            (do
              (ctl/warnf "OIDC unknown provider: %s" cb-provider)
              (unauthorized ctx))))
        (catch Exception ex
          (unauthorized ctx ex))))}))

;; adapted from https://auth0.com/blog/secure-a-clojure-web-api-with-auth0/



(defn decode-interceptor
  "Return an interceptor that decodes claims"
  [jwk-endpoint
   & {:keys [required?
             check-header
             unauthorized]
      :or {required? false
           check-header "authorization"
           unauthorized default-unauthorized}}]
  (i/interceptor
   {:enter
    (fn [ctx]
      (if-let [auth-header (get-in ctx
                                   [:request
                                    :headers
                                    check-header])]
        (try (->> auth-header
                  (clj-jwt/unsign jwk-endpoint)
                  (assoc-in ctx [:request :claims]))
             (catch Exception ex
               (log/warn :msg "Unhandled exception yielded a 401")
               (unauthorized ctx ex)))
        (if required?
          (unauthorized ctx)
          ;; TODO: namespaced keyword
          (assoc-in ctx [:request :claims] {}))))}))