(ns com.yetanalytics.pedestal-oidc.response)

(def unauthorized
  {:status 401
   :headers {}
   :body "UNAUTHORIZED"})

(def forbidden
  {:status 403
   :headers {}
   :body "FORBIDDEN"})

(defn redirect
  [url]
  {:status  302
   :headers {"Location" url}
   :body ""})
