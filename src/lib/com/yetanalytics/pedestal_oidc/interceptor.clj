(ns com.yetanalytics.pedestal-oidc.interceptor
  (:require [io.pedestal.interceptor :as i]
            [com.yetanalytics.pedestal-oidc.response :as resp]
            [com.yetanalytics.pedestal-oidc.jwt :as jwt]
            [clojure.tools.logging :as log]
            [clojure.string :as cstr]
            [clojure.core.async :as a]))

(defn default-unauthorized [ctx & [?ex & _]]
  (assoc ctx :response resp/unauthorized))

;; adapted from https://auth0.com/blog/secure-a-clojure-web-api-with-auth0/

(defn decode-enter-sync
  [ctx
   required?
   check-header
   unauthorized
   keyset]
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
                     keyset
                     access-token)))
        ;; bad auth header
        (if required?
          (unauthorized ctx)
          ctx))
      ;; no auth header
      (if required?
        (unauthorized ctx)
        ctx))
    (catch Exception ex
      (log/warn "Unhandled token decode exception yielded a 401")
      (unauthorized ctx ex))))

(defn decode-interceptor
  "Given a function that returns a map of public keys, return an interceptor
  that decodes claims and stores them on the context as
  :com.yetanalytics.pedestal-oidc/claims.

  If :async? is true, the function is expected to return a channel unless
  :keyset-blocking? is also true in which case it will be run in a thread.

  Other options:

    :required? - Return a 401 unless valid claims are present
    :unauthorized - A function that will receive the context map to handle a 401
    :check-header - the header to check for the access token
  "
  [get-keyset-fn
   & {:keys [required?
             check-header
             unauthorized
             async?
             keyset-blocking?]
      :or {required? true
           check-header "authorization"
           unauthorized default-unauthorized
           async? false
           keyset-blocking? false}}]
  (i/interceptor
   {:enter
    (fn [ctx]
      (if async?
        (a/go
          (decode-enter-sync
           ctx
           required?
           check-header
           unauthorized
           (a/<!
            (if keyset-blocking?
              (a/thread (get-keyset-fn ctx))
              (get-keyset-fn ctx)))))
        (decode-enter-sync
         ctx
         required?
         check-header
         unauthorized
         (get-keyset-fn ctx))))}))
