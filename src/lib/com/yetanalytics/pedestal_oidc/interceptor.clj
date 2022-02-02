(ns com.yetanalytics.pedestal-oidc.interceptor
  (:require [io.pedestal.interceptor :as i]
            [com.yetanalytics.pedestal-oidc.response :as resp]
            [com.yetanalytics.pedestal-oidc.jwt :as jwt]
            [clojure.tools.logging :as log]
            [clojure.string :as cstr]))

(defn default-unauthorized [ctx & [?ex & _]]
  (assoc ctx :response resp/unauthorized))

;; adapted from https://auth0.com/blog/secure-a-clojure-web-api-with-auth0/

(defn decode-interceptor
  "Given a map of valid public keys, return an interceptor that decodes claims."
  [& {:keys [required?
             check-header
             unauthorized
             jwks-uri
             pkey-map
             memo-pkeys?]
      :or {required? true
           check-header "authorization"
           unauthorized default-unauthorized
           memo-pkeys? false}}]
  (let [get-pkey-map (cond->
                         (cond
                           (map? pkey-map) (constantly pkey-map)
                           (fn? pkey-map) pkey-map
                           (and (nil? pkey-map)
                                (not-empty jwks-uri))
                           #(jwt/get-keyset jwks-uri))
                       memo-pkeys? memoize)]
    (i/interceptor
     {:enter
      (fn [ctx]
        (try
          (if-let [auth-header (get-in ctx
                                       [:request
                                        :headers
                                        check-header])]
            (if (cstr/starts-with? auth-header "Bearer ")
              (let [access-token (subs auth-header 7)]
                (assoc-in ctx
                          [:request ::claims]
                          (jwt/unsign
                           (get-pkey-map)
                           access-token))))
            (if required?
              (unauthorized ctx)
              ctx))
          (catch Exception ex
            (log/warn "Unhandled token decode exception yielded a 401")
            (unauthorized ctx ex))))})))
