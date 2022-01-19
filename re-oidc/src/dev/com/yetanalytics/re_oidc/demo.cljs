(ns ^:figwheel-hooks com.yetanalytics.re-oidc.demo
  (:require
   [goog.dom :as gdom]
   [reagent.core :as reagent :refer [atom]]
   [reagent.dom :as rdom]
   [re-frame.core :as re-frame]
   [day8.re-frame.http-fx]
   [com.yetanalytics.re-oidc :as re-oidc]
   [goog.events :as events]
   [clojure.pprint :as pp]
   [ajax.core :as ajax]))

;; Init the demo's DB
(re-frame/reg-event-db
 ::init-db
 (fn [_ _]
   {}))

(re-frame/reg-event-fx
 ::get-oidc-config!
 (fn [{:keys [db]} _]
   {:http-xhrio {:method :get
                 :uri "/oidc.json"
                 :response-format (ajax/json-response-format
                                   {:keywords? true})
                 :on-success [::recv-oidc-config]
                 :on-failure [::fail-oidc-config]}}))

(defn- push-state
  "Push history state to clean up on login/logout"
  [path]
  (.pushState js/window.history
              (clj->js {})
              js/document.title
              path))

(re-frame/reg-event-fx
 ::recv-oidc-config
 (fn [ctx [_ config]]
   {:fx [[:dispatch
          ;; Initialize OIDC from the remote config
          [::re-oidc/init
           (merge {:config
                   ;; These config options are passed directly to the OIDC client
                   config
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
                     :after-logout #(push-state "/")}))]]]}))

(re-frame/reg-event-fx
 ::fail-oidc-config
 (fn [ctx [_ {:keys [status]}]]
   (.error js/console "Failed to fetch OIDC config, status:" status)
   {}))

;; Compose init events for the demo db + OIDC's user manager
(re-frame/reg-event-fx
 ::init!
 (fn [_ _]
   {:fx [[:dispatch [::init-db]]
         ;; Fetch the OIDC config, initializing the UserManager on success
         [:dispatch [::get-oidc-config!]]]}))

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
