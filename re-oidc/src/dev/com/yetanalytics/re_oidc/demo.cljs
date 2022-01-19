(ns ^:figwheel-hooks com.yetanalytics.re-oidc.demo
  (:require
   [goog.dom :as gdom]
   [reagent.core :as reagent :refer [atom]]
   [reagent.dom :as rdom]
   [re-frame.core :as re-frame]
   [com.yetanalytics.re-oidc :as re-oidc]
   [goog.events :as events]
   [clojure.pprint :as pp])
  (:import [goog.history Html5History EventType]))

#_(defn make-history []
  (doto (Html5History.)
    ;; for SPA use
    #_(.setPathPrefix (str js/window.location.protocol
                           "//"
                           js/window.location.host))
    #_(.setUseFragment false)))

#_(defonce history
  #_(make-history)
  (delay
    (doto (make-history)
      (events/listen EventType.NAVIGATE
                     (fn [x]
                       (let [token (.-token x)]
                         (println 'token token)
                         #_(when (.startsWith token "/callback")
                           (re-frame/dispatch [::re-oidc/store-callback token])))
                       ))
      (.setEnabled true))))

;; Init the demo's DB
(re-frame/reg-event-db
 ::init-db
 (fn [_ _]
   {}))

(defn- push-state
  "Push history state to clean up on login/logout"
  [path]
  (.pushState js/window.history
              (clj->js {})
              js/document.title
              path))

;; Compose init events for the demo db + OIDC's user manager
(re-frame/reg-event-fx
 ::init!
 (fn [_ _]
   {:fx [[:dispatch [::init-db]]
         [:dispatch
          [::re-oidc/init
           (merge {:config
                   ;; These config options are passed directly to the OIDC client
                   {:authority "http://0.0.0.0:8080/auth/realms/test"
                    :client_id "testapp_public"
                    :redirect_uri "http://localhost:9500/#callback.login"
                    :response_type "code" ;; "id_token token"
                    :post_logout_redirect_uri "http://localhost:9500/#callback.logout"
                    :scope "openid profile"
                    ;; :loadUserInfo false
                    :automaticSilentRenew true
                    ;; :prompt "none"

                    ;; If this is on, creates an iframe that messes everything up
                    :monitorSession false}
                   :auto-login false}

                  ;; Callback States
                  (when (= "#callback.login"
                           js/window.location.hash)
                    (if-some [qstring (not-empty
                                      js/window.location.search)]
                      {:callback-type :login
                       :login-query-string qstring
                       ;; clear the callback fragment/go somewhere
                       :after-login #(push-state "/")}
                      (throw (ex-info "Login callback query string required"
                                      {:type ::login-qstring-required}))))
                  (when (= "#callback.logout"
                           js/window.location.hash)
                    {:callback-type :logout
                     :after-logout #(push-state "/")}))]]

         ]}))

(re-frame/reg-sub
 ::db-debug
 (fn [db _]
   db))


(defn get-app-element []
  (gdom/getElement "app"))

(defn hello-world []
  [:div
   [:h2 "DEMO"]
   [:pre (with-out-str
           (pp/pprint
            @(re-frame/subscribe [::db-debug])))]
   (if @(re-frame/subscribe [::re-oidc/logged-in?])
     [:button
      {:on-click #(re-frame/dispatch [::re-oidc/log-out])}
      "Log out"]
     [:button
      {:on-click #(re-frame/dispatch [::re-oidc/log-in])}
      "Log in"])])

(defn mount [el]
  (rdom/render [hello-world] el))

(defn mount-app-element []
  (when-let [el (get-app-element)]
    (mount el)))

;; conditionally start your application based on the presence of an "app" element
;; this is particularly helpful for testing this ns without launching the app
(defn init! []
  #_@history
  (re-frame/dispatch [::init!])
  (mount-app-element))

(defonce init
  (do
    (init!)))

;; specify reload hook with ^:after-load metadata
(defn ^:after-load on-reload []
  (println "figwheel reload!")
  (mount-app-element)
  ;; optionally touch your app-state to force rerendering depending on
  ;; your application
  ;; (swap! app-state update-in [:__figwheel_counter] inc)
)