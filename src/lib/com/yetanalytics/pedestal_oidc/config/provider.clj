(ns com.yetanalytics.pedestal-oidc.config.provider
  (:require [clojure.spec.alpha :as s]
            [clojure.spec.gen.alpha :as sgen]
            [clojure.string :as cs]))

(s/def ::config-uri string?)
(s/def ::client-id string?)
(s/def ::client-secret string?)

(s/def ::scope
  (s/with-gen
    (s/and string?
           (fn [s]
             (not (nil? (cs/index-of s "openid")))))
    (fn []
      (sgen/return "openid"))))

(s/def ::authentication-params
  (s/map-of string? string?))

(def provider-spec
  (s/keys :req-un [::config-uri
                   ::client-id
                   ::client-secret
                   ::scope]
          :opt-un [::authentication-params]))
