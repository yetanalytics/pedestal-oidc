(ns com.yetanalytics.pedestal-oidc.session
  "Session states"
  (:require [clojure.spec.alpha :as s]))

(s/def ::nonce string?)

(s/def :com.yetanalytics.pedestal-oidc.session.callback/provider string?)
(s/def :com.yetanalytics.pedestal-oidc.session.callback/return string?)
(s/def :com.yetanalytics.pedestal-oidc.session.callback/state string?)

(s/def ::callback
  (s/keys :req-un [:com.yetanalytics.pedestal-oidc.session.callback/provider
                   :com.yetanalytics.pedestal-oidc.session.callback/return
                   :com.yetanalytics.pedestal-oidc.session.callback/state]))

(s/def :com.yetanalytics.pedestal-oidc.session.identity.tokens/access-token
  string?)
(s/def :com.yetanalytics.pedestal-oidc.session.identity.tokens/refresh-token
  string?)
(s/def :com.yetanalytics.pedestal-oidc.session.identity.tokens/id-token
  string?)
(s/def :com.yetanalytics.pedestal-oidc.session.identity.tokens/expires-in
  nat-int?)

(s/def :com.yetanalytics.pedestal-oidc.session.identity/tokens
  (s/keys :req-un
          [:com.yetanalytics.pedestal-oidc.session.identity.tokens/access-token
           :com.yetanalytics.pedestal-oidc.session.identity.tokens/refresh-token
           :com.yetanalytics.pedestal-oidc.session.identity.tokens/id-token
           :com.yetanalytics.pedestal-oidc.session.identity.tokens/expires-in]))

(s/def :com.yetanalytics.pedestal-oidc.session.identity/userinfo
  (s/map-of keyword? string?))

(s/def ::identity
  (s/keys :req-un
          [#_:com.yetanalytics.pedestal-oidc.session.identity/tokens
           :com.yetanalytics.pedestal-oidc.session.identity/userinfo]))

(def session-spec
  (s/keys :req [::nonce]
          :opt [::callback
                ::identity]))

(s/fdef new-session
  :args (s/cat
         :nonce ::nonce
         :provider :com.yetanalytics.pedestal-oidc.session.callback/provider
         :state :com.yetanalytics.pedestal-oidc.session.callback/state
         :return :com.yetanalytics.pedestal-oidc.session.callback/return)
  :ret (s/keys :req [::nonce
                     ::callback]))

(defn new-session
  [nonce provider state return]
  {:com.yetanalytics.pedestal-oidc/nonce nonce
   :com.yetanalytics.pedestal-oidc/callback
   {:provider provider
    :return return
    :state state}})

(s/fdef identified-session
  :args (s/cat
         :tokens :com.yetanalytics.pedestal-oidc.session.identity/tokens
         :userinfo :com.yetanalytics.pedestal-oidc.session.identity/userinfo)
  :ret (s/keys :req [::identity]))

(defn identified-session
  [tokens userinfo]
  ^:recreate
  {::identity
   {;; :tokens tokens ;; These don't fit in cookie sessions lol
    :userinfo userinfo}})
