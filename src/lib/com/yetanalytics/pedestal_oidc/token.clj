(ns com.yetanalytics.pedestal-oidc.token
  "Token helpers"
  (:require [clojure.spec.alpha :as s]
            [com.yetanalytics.pedestal-oidc.config :as config]
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
    :azp
    })

(s/fdef validate-id-token
  :args (s/cat
         :id-token string?
         :provider ::config/provider
         :remote-config ::config/remote
         :session-nonce string?)
  :ret (s/nilable invalid-cause))

(defn validate-id-token
  "Check unsign and check the validity of the identity token per
  https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation"
  [id-token
   {:keys [client-id]}
   {:keys [issuer
           jwks-uri]}
   session-nonce]
  (try
    (let [;; Unsign
          {:keys [iss
                  nonce
                  aud
                  azp] :as tok} (clj-jwt/unsign
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
        ;; OIDC azp rules
        (or (and (vector? aud)
                 (not azp))
            (and azp
                 (not= client-id azp))) :azp
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
