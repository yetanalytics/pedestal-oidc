(ns com.yetanalytics.pedestal-oidc.interceptor
  "Some interceptors adapted from https://auth0.com/blog/secure-a-clojure-web-api-with-auth0/"
  (:require [no.nsd.clj-jwt :as clj-jwt]
            [io.pedestal.interceptor :as i]
            [io.pedestal.log :as log]))

(def unauthorized
  {:status 401
   :headers {}
   :body "UNAUTHORIZED"})

(defn decode-interceptor
  "Return an interceptor that decodes claims"
  [jwk-endpoint
   & {:keys [required?
             check-header]
      :or {required? false
           check-header "authorization"}}]
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
             (catch Exception _
               (log/warn :msg "Unhandled exception yielded a 401")
               (assoc ctx :response unauthorized)))

        (if required?
          (assoc ctx :response unauthorized)
          (assoc-in ctx [:request :claims] {}))))}))
