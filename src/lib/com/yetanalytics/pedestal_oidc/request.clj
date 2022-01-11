(ns com.yetanalytics.pedestal-oidc.request
  "Build OIDC requests"
  (:require [clojure.spec.alpha :as s]
            [com.yetanalytics.pedestal-oidc.config.provider :as provider]))

(s/fdef token-request
  :args (s/cat
         :provider provider/provider-spec
         :code string?)
  :ret map?)

(defn token-request
  "Form an OIDC token request"
  [{:keys [client-id
           client-secret
           token-endpoint]}
   code]
  {:url token-endpoint
   :method :post
   :form-params {:code code
                 :client_id client-id
                 :client_secret client-secret
                 :grant_type "authorization_code"}})

(s/fdef userinfo-request
  :args (s/cat
         :provider provider/provider-spec
         :token string?)
  :ret map?)

(defn userinfo-request
  "Form an OIDC userinfo request"
  [{:keys [userinfo-endpoint]}
   token]
  {:url userinfo-endpoint
   :method :get
   :oauth-token token})
