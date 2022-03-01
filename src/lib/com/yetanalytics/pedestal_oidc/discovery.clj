(ns com.yetanalytics.pedestal-oidc.discovery
  "OIDC discovery https://openid.net/specs/openid-connect-discovery-1_0.html"
  (:require [clojure.spec.alpha :as s]
            [cheshire.core :as json]
            [clojure.java.io :as io]
            [clojure.string :as cstr]))

(s/fdef issuer->config-uri
  :args (s/cat :issuer string?)
  :ret string?)

(defn issuer->config-uri
  [issuer]
  (str issuer
       (when-not (cstr/ends-with? issuer "/")
         "/")
       ".well-known/openid-configuration"))

(s/fdef get-openid-config
  :args (s/cat :config-uri string?)
  :ret map?)

(defn get-openid-config
  [config-uri
   & {:keys [key-fn]
      :or {key-fn str}}]
  (try (with-open [rdr (io/reader (io/input-stream config-uri))]
         (json/parse-stream rdr key-fn))
       (catch Exception ex
         (throw (ex-info "Could not retrieve openid configuration!"
                         {:type ::get-openid-config-fail
                          :config-uri config-uri}
                         ex)))))
