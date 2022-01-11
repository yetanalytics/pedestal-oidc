(ns com.yetanalytics.pedestal-oidc.interceptor
  "Some interceptors adapted from https://auth0.com/blog/secure-a-clojure-web-api-with-auth0/"
  (:require [no.nsd.clj-jwt :as clj-jwt]
            [io.pedestal.interceptor :as i]
            [io.pedestal.log :as log]
            [com.yetanalytics.pedestal-oidc.response :as resp]))

(defn default-decode-unauthorized [ctx & _]
  (assoc ctx :response resp/unauthorized))

(defn decode-interceptor
  "Return an interceptor that decodes claims"
  [jwk-endpoint
   & {:keys [required?
             check-header
             unauthorized]
      :or {required? false
           check-header "authorization"
           unauthorized default-decode-unauthorized}}]
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
          (assoc-in ctx [:request :claims] {}))))}))
