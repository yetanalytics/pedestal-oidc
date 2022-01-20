(ns com.yetanalytics.re-oidc.user
  (:require [clojure.spec.alpha :as s :include-macros true]))

(s/def ::any-json ;; arbitrary JSON
  (s/nilable
   (s/or :scalar
         (s/or :string
               string?
               :number
               (s/or :double
                     (s/double-in :infinite? false :NaN? false)
                     :int
                     int?)
               :boolean
               boolean?)
         :coll
         (s/or :map
               (s/map-of
                string?
                ::any-json
                :gen-max 4)
               :vector
               (s/coll-of
                ::any-json
                :kind vector?
                :into []
                :gen-max 4)))))

(s/def ::refresh-token string?)
(s/def ::expires-at pos-int?)
(s/def ::state (s/nilable string?))
(s/def ::scope string?)
(s/def ::id-token string?)
(s/def ::access-token string?)
(s/def ::token-type #{"Bearer"})
(s/def ::session-state string?)
(s/def ::profile
  (s/map-of string?
            ::any-json))

(def user-spec
  (s/keys :req-un [::refresh-token
                   ::expires-at
                   ::state
                   ::scope
                   ::id-token
                   ::access-token
                   ::token-type
                   ::session-state
                   ::profile]))
