(ns com.yetanalytics.pedestal-oidc.util
  (:import [java.security SecureRandom]))

;; After https://github.com/propan/geheimtur/blob/master/src/geheimtur/impl/oauth2.clj#L12
(defn generate-state
  "Creates a random state token"
  []
  (.toString (BigInteger. 130 (SecureRandom.)) 32))

(defn generate-nonce
  "Creates a random nonce token"
  []
  (.toString (BigInteger. 130 (SecureRandom.)) 32))
