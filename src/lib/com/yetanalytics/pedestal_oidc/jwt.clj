(ns com.yetanalytics.pedestal-oidc.jwt
  (:require [clojure.spec.alpha :as s]
            [com.yetanalytics.pedestal-oidc.config.remote :as remote]
            [cheshire.core :as json]
            [clojure.java.io :as io]
            [buddy.core.keys :as bkeys]
            [buddy.sign.jwt :as jwt]))

(s/def ::kid string?)

(s/def ::pkey-map
  (s/map-of ::kid
            bkeys/public-key?))

(s/fdef get-jwks-pkeys
  :args (s/cat :jwks-uri ::remote/jwks-uri)
  :ret ::pkey-map)

(defn get-jwks-pkeys
  [jwks-uri]
  (try (-> (with-open [rdr (io/reader (io/input-stream jwks-uri))]
             (json/parse-stream rdr #(keyword nil %)))
           :keys
           (->> (map (fn [pkey]
                       [(:kid pkey) (bkeys/jwk->public-key pkey)]))
                (into {})))
       (catch Exception ex
         (throw (ex-info "Could not retrieve public keys!"
                         {:type ::jwks-public-key
                          :jwks-uri jwks-uri}
                         ex)))))

(s/fdef unsign
  :args (s/cat
         :pkey-map ::pkey-map
         :jwt string?
         :opts (s/? map?))
  :ret map?)

(defn unsign
  "Attempt to unsign a JWT token according to OIDC"
  [pkey-map
   jwt
   & [opts]]
  (jwt/unsign
   jwt
   (fn [{:keys [kid]}]
     (get pkey-map kid))
   (merge {:alg :rs256} opts)))
