(ns com.yetanalytics.pedestal-oidc.jwt
  (:require [clojure.spec.alpha :as s]
            [cheshire.core :as json]
            [clojure.java.io :as io]
            [buddy.core.keys :as bkeys]
            [buddy.sign.jwt :as jwt]))

(s/def ::kid string?)

(s/def ::keyset
  (s/or :map (s/map-of ::kid
                       bkeys/public-key?)
        ;; Keyset can be a function that takes the :kid
        :function (s/fspec
                   :args (s/cat :kid ::kid)
                   :ret (s/nilable bkeys/public-key?))))

(s/fdef get-keyset
  :args (s/cat :jwks-uri string?)
  :ret ::keyset)

(defn get-keyset
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
         :keyset ::keyset
         :jwt string?
         :opts (s/? map?))
  :ret map?)

(defn unsign
  "Attempt to unsign a JWT token according to OIDC"
  [keyset
   jwt
   & [opts]]
  (jwt/unsign
   jwt
   (fn [{:keys [kid]}]
     (or (keyset kid)
         (throw (ex-info "JWT Key ID Not Found"
                         {:type ::kid-not-found
                          :kid kid}))))
   (merge {:alg :rs256} opts)))
