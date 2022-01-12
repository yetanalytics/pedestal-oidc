(ns com.yetanalytics.pedestal-oidc.identity
  "Token/identity ops"
  (:require [clojure.spec.alpha :as s]))

(s/def :com.yetanalytics.pedestal-oidc.identity.tokens/access-token
  string?)
(s/def :com.yetanalytics.pedestal-oidc.identity.tokens/refresh-token
  string?)
(s/def :com.yetanalytics.pedestal-oidc.identity.tokens/id-token
  string?)
(s/def :com.yetanalytics.pedestal-oidc.identity.tokens/token-type
  #{"Bearer"})

(s/def ::tokens
  (s/keys :req-un
          [:com.yetanalytics.pedestal-oidc.identity.tokens/access-token
           :com.yetanalytics.pedestal-oidc.identity.tokens/refresh-token
           :com.yetanalytics.pedestal-oidc.identity.tokens/id-token
           :com.yetanalytics.pedestal-oidc.identity.tokens/token-type]))

(s/def ::provider simple-keyword?)

(def identity-spec
  (s/keys :req-un
          [::provider
           ::tokens]))
