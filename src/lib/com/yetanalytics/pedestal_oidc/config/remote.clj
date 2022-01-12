(ns com.yetanalytics.pedestal-oidc.config.remote
  (:require [clojure.spec.alpha :as s]))

;; https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
;; There are more keys than we use, so spec is partial

(s/def ::authorization-endpoint string?)
(s/def ::token-endpoint string?)
(s/def ::userinfo-endpoint string?)
(s/def ::jwks-uri string?)

(def remote-spec
  (s/keys :req-un [::authorization-endpoint
                   ::token-endpoint
                   ::user-info-endpoint
                   ::jwks-uri]))
