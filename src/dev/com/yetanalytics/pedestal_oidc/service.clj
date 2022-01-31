(ns com.yetanalytics.pedestal-oidc.service
  (:require [io.pedestal.http :as http]
            [io.pedestal.http.route :as route]
            [io.pedestal.http.body-params :as body-params]
            [ring.middleware.session.cookie :as cookie]
            [ring.middleware.session.memory :as memory]
            [ring.util.response :as ring-resp]
            [com.yetanalytics.pedestal-oidc.config :as config]
            [com.yetanalytics.pedestal-oidc.interceptor :as i]
            [clojure.pprint :as pp]))

;; http://0.0.0.0:8080/auth/realms/test/.well-known/openid-configuration

#_(def oidc-config
  (config/get-local "pedestal-oidc.edn"))

#_(defn about-page
  [request]
  (ring-resp/response (format "Clojure %s - served from %s"
                              (clojure-version)
                              (route/url-for ::about-page))))

#_(defn home-page
  [{:keys [session]}]
  (ring-resp/response
   (format
    "<div>%s%s</div>"
    (apply format
           "<a href=\"%s\">%s</a>"
           (if (:com.yetanalytics.pedestal-oidc.session/identity session)
             ["/oidc/logout" "Log Out"]
             ["/oidc/login" "Log In"]))
    (format
     "<pre>%s</pre>"
     (with-out-str
       (pp/pprint session))))))

;; Defines "/" and "/about" routes with their associated :get handlers.
;; The interceptors defined after the verb map (e.g., {:get home-page}
;; apply to / and its children (/about).
#_(def common-interceptors [(body-params/body-params)
                          http/html-body])

(defn echo-claims
  [req]
  {:status 200
   :headers {}
   :body (::i/claims req)})

;; Example API decoding claims
(def routes #{["/api" :get
               [(body-params/body-params)
                http/json-body
                (i/decode-interceptor
                 :jwks-uri "http://0.0.0.0:8080/auth/realms/test/protocol/openid-connect/certs")
                `echo-claims]]})


#_(def routes #{["/" :get (conj common-interceptors `home-page)]
              ["/about" :get (conj common-interceptors `about-page)]
              ["/oidc/login" :get (into common-interceptors
                                        [(i/login-redirect-interceptor
                                          oidc-config
                                          "http://0.0.0.0:8081/oidc/callback")])
               :route-name :com.yetanalytics.pedestal-oidc/login]
              ["/oidc/callback" :get (into common-interceptors
                                           [(i/login-callback-interceptor
                                             oidc-config
                                             "http://0.0.0.0:8081/oidc/callback")])
               :route-name :com.yetanalytics.pedestal-oidc/callback]
              ["/oidc/logout" :get (into common-interceptors
                                         [(i/logout-interceptor
                                           oidc-config)])
               :route-name :com.yetanalytics.pedestal-oidc/logout]})

;; Map-based routes
;(def routes `{"/" {:interceptors [(body-params/body-params) http/html-body]
;                   :get home-page
;                   "/about" {:get about-page}}})

;; Terse/Vector-based routes
;(def routes
;  `[[["/" {:get home-page}
;      ^:interceptors [(body-params/body-params) http/html-body]
;      ["/about" {:get about-page}]]]])


;; Consumed by ped-test.server/create-server
;; See http/default-interceptors for additional options you can configure
(def service {:env :prod
              ;; You can bring your own non-default interceptors. Make
              ;; sure you include routing and set it up right for
              ;; dev-mode. If you do, many other keys for configuring
              ;; default interceptors will be ignored.
              ;; ::http/interceptors []
              ::http/routes routes

              ;; Uncomment next line to enable CORS support, add
              ;; string(s) specifying scheme, host and port for
              ;; allowed source(s):
              ;;
              ;; "http://localhost:8080"
              ;;
              ;;::http/allowed-origins ["scheme://host:port"]

              ;; Tune the Secure Headers
              ;; and specifically the Content Security Policy appropriate to your service/application
              ;; For more information, see: https://content-security-policy.com/
              ;;   See also: https://github.com/pedestal/pedestal/issues/499
              ;;::http/secure-headers {:content-security-policy-settings {:object-src "'none'"
              ;;                                                          :script-src "'unsafe-inline' 'unsafe-eval' 'strict-dynamic' https: http:"
              ;;                                                          :frame-ancestors "'none'"}}

              ;; Root for resource interceptor that is available by default.
              ::http/resource-path "/public"

              ;; Either :jetty, :immutant or :tomcat (see comments in project.clj)
              ;;  This can also be your own chain provider/server-fn -- http://pedestal.io/reference/architecture-overview#_chain_provider
              ::http/type :jetty
              ;;::http/host "localhost"
              ::http/port 8081
              ;; Options to pass to the container (Jetty)
              ::http/container-options {:h2c? true
                                        :h2? false
                                        ;:keystore "test/hp/keystore.jks"
                                        ;:key-password "password"
                                        ;:ssl-port 8443
                                        :ssl? false}
              #_#_::http/enable-session {:store
                                     #_(cookie/cookie-store)
                                     (memory/memory-store)}})
