(ns com.yetanalytics.pedestal-oidc.token
  "Token helpers"
  (:require [clojure.spec.alpha :as s]
            [com.yetanalytics.pedestal-oidc.config :as config]
            [com.yetanalytics.pedestal-oidc.identity :as ident]))

;; TODO: move id token validation per spec here
(s/fdef valid-identity-tokens?
  :args (s/cat :tokens ::ident/tokens
               :local-config ::config/local
               :remote-config ::config/remote
               ))
