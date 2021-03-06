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
        (is (= {:com.yetanalytics.pedestal-oidc/token jwt
                :request
                {:headers
                 {"authorization" auth-header},
                 :com.yetanalytics.pedestal-oidc/claims {:bar "baz"}}}
               (enter {:request {:headers {"authorization" auth-header}}})))))
    (testing "passes through unsign args"
      (let [{:keys [enter]} (decode-interceptor
                             get-keyset-fn
                             ;; verify audience
                             :unsign-opts {:aud "foo"})]
        (is (= {:bar "baz"
                :aud "foo"}
               (-> (enter {:request
                           {:headers
                            {"authorization"
                             (format "Bearer %s"
                                     (jwt/sign
                                      {:bar "baz"
                                       :aud "foo"}
                                      privkey
                                      {:alg :rs256
                                       :header {:kid "foo"}}))}}})
                   :request
                   :com.yetanalytics.pedestal-oidc/claims)))
        (is (= 401
               (-> (enter {:request
                           {:headers
                            {"authorization"
                             (format "Bearer %s"
                                     (jwt/sign
                                      {:bar "baz"
                                       :aud "quxx"}
                                      privkey
                                      {:alg :rs256
                                       :header {:kid "foo"}}))}}})
                   :response
                   :status)))))
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
        (is (= {:com.yetanalytics.pedestal-oidc/token jwt
                :request
                {:headers
                 {"authorization" auth-header},
                 :com.yetanalytics.pedestal-oidc/claims {:bar "baz"}}}
               (a/<!! (enter {:request {:headers {"authorization" auth-header}}}))))))))
