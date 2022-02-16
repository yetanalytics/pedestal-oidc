(ns com.yetanalytics.pedestal-oidc.interceptor-test
  (:require [clojure.test :refer :all]
            [com.yetanalytics.pedestal-oidc.interceptor :refer :all]
            [buddy.core.keys :as bkeys]
            [buddy.sign.jwt :as jwt]
            [clojure.core.async :as a]))

(deftest decode-interceptor-test
  (let [privkey (bkeys/private-key "dev-resources/keys/privkey.pem" "insecure")
        pubkey (bkeys/public-key "dev-resources/keys/pubkey.pem")
        jwt (jwt/sign
             {:bar "baz"}
             privkey
             {:alg :rs256
              :header {:kid "foo"}})
        auth-header (format "Bearer %s" jwt)
        get-keyset-fn (fn [& _] {"foo" pubkey})]
    (testing "decodes, sync"
      (let [{:keys [enter]} (decode-interceptor
                             get-keyset-fn)]
        (is (= {:com.yetanalytics.pedestal-oidc/token "eyJhbGciOiJSUzI1NiIsImtpZCI6ImZvbyJ9.eyJiYXIiOiJiYXoifQ.hFdq5YhGabJUl9gemxt7lmNMEDyTL7A3z_i1qk-1NdU48yljsLTfa7tsZQuHtQzmJVJxBDX7GJ4f-0a_b6NMuIZ2ekYUiR__S4pzElaK0jP0DECV8Z54fo0Uq3LhhItF0BwjgjIKYKc1a8Sk5y9W9gRrFAcFbQr5e8GUO5vRjqA"
                :request
                {:headers
                 {"authorization"
                  "Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImZvbyJ9.eyJiYXIiOiJiYXoifQ.hFdq5YhGabJUl9gemxt7lmNMEDyTL7A3z_i1qk-1NdU48yljsLTfa7tsZQuHtQzmJVJxBDX7GJ4f-0a_b6NMuIZ2ekYUiR__S4pzElaK0jP0DECV8Z54fo0Uq3LhhItF0BwjgjIKYKc1a8Sk5y9W9gRrFAcFbQr5e8GUO5vRjqA"},
                 :com.yetanalytics.pedestal-oidc/claims {:bar "baz"}}}
               (enter {:request {:headers {"authorization" auth-header}}})))))
    (testing "fails 401 by default"
      (let [{:keys [enter]} (decode-interceptor
                             get-keyset-fn)]
        (is (= 401
               (get-in
                (enter {:request {:headers {}}})
                [:response :status])))))
    (testing "failure types"
      (let [{:keys [enter]} (decode-interceptor
                             get-keyset-fn)
            bad-header (subs auth-header 0 233)
            unknown-jwt (jwt/sign
                         {:bar "baz"}
                         privkey
                         {:alg :rs256
                          :header {:kid "bar"}})
            unknown-header (format "Bearer %s" unknown-jwt)]
        (are [ctx-in failure-type]
            (= failure-type
               (get
                (enter ctx-in)
                :com.yetanalytics.pedestal-oidc/failure))

          {:request {:headers {}}}                               :header-missing
          {:request {:headers {"authorization" ""}}}             :header-invalid
          {:request {:headers {"authorization" bad-header}}}     :token-invalid
          {:request {:headers {"authorization" unknown-header}}} :kid-not-found))
      (testing "keyset failures"
        (let [{:keys [enter]} (decode-interceptor
                               #(throw (ex-info "uh oh"
                                                {:type ::uh-oh})))]
          (is (= :keyset-error
                 (get
                  (enter {:request {:headers {"authorization" auth-header}}})
                  :com.yetanalytics.pedestal-oidc/failure))))
        (let [{:keys [enter]} (decode-interceptor
                               (constantly nil))]
          (is (= :keyset-invalid
                 (get
                  (enter {:request {:headers {"authorization" auth-header}}})
                  :com.yetanalytics.pedestal-oidc/failure))))))
    (testing "decodes, async"
      (let [{:keys [enter]} (decode-interceptor
                             (fn [_]
                               (a/go (get-keyset-fn)))
                             :async? true)]
        (is (= {:com.yetanalytics.pedestal-oidc/token "eyJhbGciOiJSUzI1NiIsImtpZCI6ImZvbyJ9.eyJiYXIiOiJiYXoifQ.hFdq5YhGabJUl9gemxt7lmNMEDyTL7A3z_i1qk-1NdU48yljsLTfa7tsZQuHtQzmJVJxBDX7GJ4f-0a_b6NMuIZ2ekYUiR__S4pzElaK0jP0DECV8Z54fo0Uq3LhhItF0BwjgjIKYKc1a8Sk5y9W9gRrFAcFbQr5e8GUO5vRjqA"
                :request
                {:headers
                 {"authorization"
                  "Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImZvbyJ9.eyJiYXIiOiJiYXoifQ.hFdq5YhGabJUl9gemxt7lmNMEDyTL7A3z_i1qk-1NdU48yljsLTfa7tsZQuHtQzmJVJxBDX7GJ4f-0a_b6NMuIZ2ekYUiR__S4pzElaK0jP0DECV8Z54fo0Uq3LhhItF0BwjgjIKYKc1a8Sk5y9W9gRrFAcFbQr5e8GUO5vRjqA"},
                 :com.yetanalytics.pedestal-oidc/claims {:bar "baz"}}}
               (a/<!! (enter {:request {:headers {"authorization" auth-header}}}))))))))
