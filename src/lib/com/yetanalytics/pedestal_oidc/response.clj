(ns com.yetanalytics.pedestal-oidc.response)

(def unauthorized
  {:status 401
   :headers {}
   :body "UNAUTHORIZED"
   :session nil})
