(ns com.yetanalytics.pedestal-oidc.token
  "Token helpers"
  (:require [clojure.spec.alpha :as s]
            [com.yetanalytics.pedestal-oidc.config :as config]
            [com.yetanalytics.pedestal-oidc.identity :as ident]
            [no.nsd.clj-jwt :as clj-jwt]))

(def invalid-cause
  #{;; From buddy-sign
    :iss
    :aud ;; special case, can be an array in OIDC
    :exp
    :nbf
    ;; we don't pass/check these yet
    ;; :max-age
    ;; :sub

    ;; oidc only
    :nonce
    })

(s/fdef validate-identity-tokens
  :args (s/cat
         :provider ::config/provider
         :remote-config ::config/remote
         :tokens ::ident/tokens
         :session-nonce string?)
  :ret (s/nilable invalid-cause))

(defn validate-identity-tokens
  "Check unsign and check the validity of the identity tokens map per
  https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation"
  [{:keys [client-id]}
   {:keys [issuer
           jwks-uri]}
   {:keys [id-token
           access-token
           refresh-token] :as tokens}
   session-nonce]
  (try
    (let [;; Unsign
          {:keys [iss
                  nonce
                  aud] :as tok} (clj-jwt/unsign
                                 jwks-uri
                                 id-token
                                 {:iss issuer})]
      (cond
        ;; Nonce mismatch is some kind of funny business
        (not= session-nonce nonce) :nonce
        ;; OIDC says aud can be a string or array
        (or (and (string? aud)
                 (not= client-id aud))
            (and (vector? aud)
                 (not (contains? (set aud) client-id)))) :aud
        ;; If everything is OK, return nil
        :else nil))
    (catch clojure.lang.ExceptionInfo exi
      (let [{exi-type :type
             exi-cause :cause} (ex-data exi)]
        (if (= exi-type
               :validation)
          exi-cause
          ;; anything else is unhandled and should bubble
          (throw exi))))))
