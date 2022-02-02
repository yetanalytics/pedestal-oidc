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
             get-keyset-fn]
      :or {required? true
           check-header "authorization"
           unauthorized default-unauthorized}}]
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
                        [:request
                         :com.yetanalytics.pedestal-oidc/claims]
                        (jwt/unsign
                         (get-keyset-fn ctx)
                         access-token))))
          (if required?
            (unauthorized ctx)
            ctx))
        (catch Exception ex
          (log/warn "Unhandled token decode exception yielded a 401")
          (unauthorized ctx ex))))}))
