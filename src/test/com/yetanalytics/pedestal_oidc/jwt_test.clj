(ns com.yetanalytics.pedestal-oidc.jwt-test
  (:require [clojure.test :refer :all]
            [com.yetanalytics.pedestal-oidc.jwt :refer :all]
            [buddy.core.keys :as bkeys]
            [buddy.sign.jwt :as jwt]))

(deftest unsign-test
  (let [privkey (bkeys/private-key "dev-resources/keys/privkey.pem" "insecure")
        pubkey (bkeys/public-key "dev-resources/keys/pubkey.pem")
        keyset {"foo" pubkey}
        jwt (jwt/sign
             {:bar "baz"}
             privkey
             {:alg :rs256
              :header {:kid "foo"}})]
    (is
     (= {:bar "baz"}
        (unsign
         keyset
         jwt)))))
