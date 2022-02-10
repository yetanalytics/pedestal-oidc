(ns com.yetanalytics.pedestal-oidc.jwt-test
  (:require [clojure.test :refer :all]
            [com.yetanalytics.pedestal-oidc.jwt :refer :all]
            [buddy.core.keys :as bkeys]
            [buddy.sign.jwt :as jwt]))

(deftest get-keyset-test
  (is (=
       {"foo" (bkeys/public-key "dev-resources/keys/pubkey.pem")}
       (get-keyset "dev-resources/keys/jwks.json"))))

(deftest unsign-test
  (let [privkey (bkeys/private-key "dev-resources/keys/privkey.pem" "insecure")
        pubkey (bkeys/public-key "dev-resources/keys/pubkey.pem")]
    (testing "map keyset"
      (is
       (= {:bar "baz"}
          (unsign
           {"foo" pubkey}
           (jwt/sign
            {:bar "baz"}
            privkey
            {:alg :rs256
             :header {:kid "foo"}})))))
    (testing "function keyset"
      (is
       (= {:bar "baz"}
          (unsign
           (fn [kid]
             (when (= "foo" kid)
               pubkey))
           (jwt/sign
            {:bar "baz"}
            privkey
            {:alg :rs256
             :header {:kid "foo"}})))))))
