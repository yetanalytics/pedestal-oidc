(ns com.yetanalytics.pedestal-oidc.service
  (:require [io.pedestal.http :as http]
            [io.pedestal.http.route :as route]
            [io.pedestal.http.body-params :as body-params]
            [ring.util.response :as ring-resp]
            [com.yetanalytics.pedestal-oidc.interceptor :as i]
            [com.yetanalytics.pedestal-oidc.jwt :as jwt]
            [com.yetanalytics.pedestal-oidc.discovery :as disco]))

;; http://0.0.0.0:8080/auth/realms/test/.well-known/openid-configuration

(defn echo-claims
  [req]
  {:status 200
   :headers {}
   :body (:com.yetanalytics.pedestal-oidc/claims req)})

;; Example API decoding claims
(def routes #{["/api" :get
               [(body-params/body-params)
                http/json-body
                (i/decode-interceptor
                 ;; How you retrieve/cache the config & keyset is up to you
                 ;; the interceptor gives this function the context in case
                 ;; you need access to something in there to get it
                 (fn [ctx]
                   (-> "http://0.0.0.0:8080/auth/realms/test" ;; the issuer
                       ;; Derive the config uri
                       disco/issuer->config-uri
                       ;; go get the config
                       disco/get-openid-config
                       ;; read the jwks uri
                       (get "jwks_uri")
                       ;; go get the keyset
                       jwt/get-keyset))

                 ;; If you want to handle failures differently:

                 ;; :unauthorized
                 ;; (fn [{attempt ::attempt
                 ;;       :as ctx
                 ;;       :or {attempt 0}} failure & [?ex]]
                 ;;   (println "fail!" failure)
                 ;;   (if (< attempt 5)
                 ;;     (-> ctx
                 ;;         (update ::attempt (fnil inc 0))
                 ;;         i/retry-decode)
                 ;;     (i/default-unauthorized ctx failure ?ex)))
                 )
                `echo-claims]]})

(def service {:env :prod
              ::http/routes routes

              ;; Uncomment next line to enable CORS support, add
              ;; string(s) specifying scheme, host and port for
              ;; allowed source(s):
              ;;
              ;; "http://localhost:8080"
              ;;
              ::http/allowed-origins ["*"]

              ::http/resource-path "/public"

              ;; Either :jetty, :immutant or :tomcat (see comments in project.clj)
              ;;  This can also be your own chain provider/server-fn -- http://pedestal.io/reference/architecture-overview#_chain_provider
              ::http/type :jetty
              ;;::http/host "localhost"
              ::http/port 8081
              ;; Options to pass to the container (Jetty)
              ::http/container-options {:h2c? true
                                        :h2? false
                                        :ssl? false}})
