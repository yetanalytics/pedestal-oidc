(ns com.yetanalytics.pedestal-oidc.interceptor
  (:require [io.pedestal.interceptor :as i]
            [com.yetanalytics.pedestal-oidc.response :as resp]
            [com.yetanalytics.pedestal-oidc.jwt :as jwt]
            [clojure.tools.logging :as log]
            [clojure.string :as cstr]
            [clojure.core.async :as a]))

(defn default-unauthorized
  "Default handler for any failure.
  Will receive a failure keyword and possibly an exception"
  [ctx failure & [?ex_]]
  (assoc ctx
         :response resp/unauthorized
         :com.yetanalytics.pedestal-oidc/failure failure))

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
          (try
            (-> ctx
                (assoc :com.yetanalytics.pedestal-oidc/token access-token)
                (assoc-in [:request
                           :com.yetanalytics.pedestal-oidc/claims]
                          (jwt/unsign
                           keyset
                           access-token)))
            (catch clojure.lang.ExceptionInfo exi
              (case (some-> exi
                            ex-data
                            :type)
                ;; Unknown Key
                ::jwt/kid-not-found
                (unauthorized ctx :kid-not-found exi)
                ;; Invalid Key per buddy-sign
                :validation
                (unauthorized ctx :token-invalid exi)
                ;; Throw to top-level handling
                (throw exi)))))
        ;; bad auth header
        (if required?
          (unauthorized ctx :header-invalid)
          ctx))
      ;; no auth header
      (if required?
        (unauthorized ctx :header-missing)
        ctx))
    (catch Exception ex
      (log/warn "Unknown failure yielded a 401")
      (unauthorized ctx :unknown ex))))

(defn decode-interceptor
  "Given a function that returns a map of public keys, return an interceptor
  that decodes claims and stores them on the context as
  :com.yetanalytics.pedestal-oidc/claims.

  If :async? is true, the function is expected to return a channel unless
  :keyset-blocking? is also true in which case it will be run in a thread.

  Other options:

    :required? - Return a 401 unless valid claims are present.
    :unauthorized - A function that will receive the context map to handle a 401,
      a failure keyword and possibly an exception.
    :check-header - the header to check for the access token.
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
          (if-some [keyset (a/<!
                            (if keyset-blocking?
                              (a/thread (get-keyset-fn ctx))
                              (get-keyset-fn ctx)))]
            (decode-enter-sync
             ctx
             required?
             check-header
             unauthorized
             keyset)
            (unauthorized ctx :keyset-invalid)))
        (try
          (if-some [keyset (get-keyset-fn ctx)]
            (decode-enter-sync
             ctx
             required?
             check-header
             unauthorized
             keyset)
            (unauthorized ctx :keyset-invalid))
          (catch Exception ex
            (unauthorized ctx :keyset-error ex)))))}))
