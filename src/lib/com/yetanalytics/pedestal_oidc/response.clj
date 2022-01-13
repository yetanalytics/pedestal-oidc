(ns com.yetanalytics.pedestal-oidc.response)

(def unauthorized
  {:status 401
   :headers {}
   :body "UNAUTHORIZED"
   :session nil})

(def forbidden
  {:status 403
   :headers {}
   :body "FORBIDDEN"
   :session nil})

(defn redirect
  [url]
  {:status  302
   :headers {"Location" url}
   :body ""})
