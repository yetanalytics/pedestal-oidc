(ns com.yetanalytics.pedestal-oidc.config.provider
  (:require [clojure.spec.alpha :as s]))

(s/def ::client-id string?)
(s/def ::client-secret string?)
(s/def ::authorization-endpoint string?)
(s/def ::token-endpoint string?)
(s/def ::user-info-endpoint string?)

(def provider-spec
  (s/keys :req-un [::client-id
                   ::client-secret
                   ::authorization-endpoint
                   ::token-endpoint
                   ::user-info-endpoint]))
