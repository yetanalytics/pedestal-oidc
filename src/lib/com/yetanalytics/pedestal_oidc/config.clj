(ns com.yetanalytics.pedestal-oidc.config
  (:require [clojure.spec.alpha :as s]
            [com.yetanalytics.pedestal-oidc.config.provider :as provider]))

(s/def ::providers
  (s/map-of simple-keyword?
            provider/provider-spec
            :min-count 1))

(def config-spec
  (s/keys :req-un [::providers]))
