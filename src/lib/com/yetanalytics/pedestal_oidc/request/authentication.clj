(ns com.yetanalytics.pedestal-oidc.request.authentication
  "https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest"
  (:require [clojure.spec.alpha :as s]
            [com.yetanalytics.pedestal-oidc.config.provider :as provider]
            [ring.util.codec :as codec]))

(s/fdef build-url
  :args (s/cat :provider provider/provider-spec
               :redirect-uri string?
               :state string?
               :nonce string?)
  :ret string?)

(defn build-url
  "Given a provider, redirect uri state and nonce, build a redirect url"
  [{:keys [client-id
           authorization-endpoint
           scope
           authentication-params]}
   redirect-uri
   state
   nonce]
  (format
   "%s?%s"
   authorization-endpoint
   (codec/form-encode
    (merge
     {"scope" scope
      "response_type" "code"
      "client_id" client-id
      "redirect_uri" redirect-uri
      "state" state
      "nonce" nonce}
     authentication-params))))
