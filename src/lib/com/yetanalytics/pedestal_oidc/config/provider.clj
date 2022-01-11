(ns com.yetanalytics.pedestal-oidc.config.provider
  (:require [clojure.spec.alpha :as s]
            [clojure.spec.gen.alpha :as sgen]
            [clojure.string :as cs]))

(s/def ::client-id string?)
(s/def ::client-secret string?)

(s/def ::authorization-endpoint string?)
(s/def ::token-endpoint string?)
(s/def ::user-info-endpoint string?)

(s/def ::scope
  (s/with-gen
    (s/and string?
           (fn [s]
             (not (nil? (cs/index-of s "openid")))))
    (fn []
      (sgen/return "openid"))))


(def provider-spec
  (s/keys :req-un [::client-id
                   ::client-secret
                   ::authorization-endpoint
                   ::token-endpoint
                   ::user-info-endpoint
                   ::scope]))
