(ns com.yetanalytics.pedestal-oidc.config
  (:require [clojure.spec.alpha :as s]
            [com.yetanalytics.pedestal-oidc.config.provider :as provider]
            [com.yetanalytics.pedestal-oidc.config.remote :as remote]
            [cheshire.core :as json]
            [clojure.java.io :as io]
            [camel-snake-kebab.core :as csk]
            [clojure.edn :as edn])
  (:import [java.io PushbackReader]))

(s/def ::remote remote/remote-spec)
(s/def ::provider provider/provider-spec)

(s/def ::providers
  (s/map-of simple-keyword?
            ::provider
            :min-count 1))

(def config-spec
  (s/keys :req-un [::providers]))

(s/def ::local config-spec)

(s/fdef get-local
  :args (s/cat :path (s/? string?))
  :ret config-spec)

(defn get-local
  "Get this application's config from disk"
  [& [loc]]
  (let [loc (or loc
                "pedestal-oidc.edn")]
    (try
      (with-open [rdr (PushbackReader. (io/reader loc))]
        (edn/read rdr))
      (catch Exception ex
        (throw (ex-info (format "Cant't find config at %s" loc)
                        {:type ::local-config-read-error
                         :location loc}
                        ex))))))

(s/fdef get-remote
  :args (s/cat :provider ::provider)
  :ret remote/remote-spec)

(defn get-remote
  "Attempt to get OIDC config from a well-known uri"
  [{:keys [config-uri] :as provider}]
  (try
    (with-open [rdr (io/reader config-uri)]
      (json/parse-stream rdr csk/->kebab-case-keyword))
    (catch Exception ex
      (throw (ex-info "OIDC Config Read Error"
                      {:type ::oidc-config-read-error
                       :provider provider}
                      ex)))))
