(ns com.yetanalytics.re-oidc
  (:require [cljsjs.oidc-client :refer [UserManager]]
            [re-frame.core :as re-frame]))

;; status: :init, :loaded, :unloaded

(defonce user-manager
  (atom nil))

(defn- dispatch-cb
  [k]
  (fn [& args]
    (re-frame/dispatch (into [k] args))))

(defn reg-events!
  "Register event callbacks to re-frame on the OIDC UserManager"
  [^UserManager user-manager]
  (doto user-manager.events
    (.addUserLoaded
     (dispatch-cb ::user-loaded))
    (.addUserUnloaded
     (dispatch-cb ::user-unloaded))
    ;; We set automaticSilentRenew to true and these are done for us
    #_(.addAccessTokenExpiring
     (dispatch-cb ::access-token-expiring))
    #_(.addAccessTokenExpired
     (dispatch-cb ::access-token-expired))
    (.addSilentRenewError
     (dispatch-cb ::silent-renew-error))
    ;; session monitoring requires an iframe
    ;; this breaks Figwheel and makes dev hard
    ;; TODO: enable on-demand for those with iframe-friendly idp settings
    #_(.addUserSignedIn
     (dispatch-cb ::user-signed-in))
    #_(.addUserSignedOut
     (dispatch-cb ::user-signed-out))
    #_(.addUserSessionChanged
     (dispatch-cb ::user-session-changed))))


(defn init!
  "Initialize the OIDC UserManager from config. Idempotent"
  [user-manager config]
  (if user-manager
    user-manager
    (doto (UserManager. (clj->js config))
      reg-events!)))

(defn- push-state
  "Push history state to clean up on login/logout"
  [path]
  (.pushState js/window.history
              (clj->js {})
              js/document.title
              path))

(re-frame/reg-fx
 ::init-fx
 (fn [{:keys [config
              auto-login

              after-login-callback
              catch-login-callback
              after-logout-callback
              catch-logout-callback]}]
   (let [manager (swap! user-manager init! config)
         loc-hash js/window.location.hash
         loc-search (not-empty js/window.location.search)]
     ;; TODO: this is brittle. figure out good api to incorp. with routing
     (cond
       (and (= "#callback.login" loc-hash)
            loc-search)
       (do
         (push-state "/")
         (-> manager
             (.signinRedirectCallback loc-search)
             (cond->
                 catch-login-callback
               (.catch catch-login-callback)
               after-login-callback
               (.then after-login-callback))))
       (= "#callback.logout" loc-hash)
       (do
         (push-state "/")
         (-> manager
             (.signoutRedirectCallback)
             (cond->
                 catch-logout-callback
               (.catch catch-logout-callback)
               after-logout-callback
               (.then after-logout-callback))))

       :else
       ;; If a user is present, reflect in the db
       (-> manager
           .getUser
           (.then
            (fn [?user]
              (if ?user
                (re-frame/dispatch [::user-loaded ?user])
                (when auto-login
                  (re-frame/dispatch [::log-in]))))))))))

(re-frame/reg-fx
 ::signin-redirect-fx
 (fn [{:keys [then-fn
              catch-fn]}]
   (cond-> (.signinRedirect @user-manager)
     catch-fn (.catch catch-fn)
     then-fn (.then then-fn))))

(re-frame/reg-fx
 ::signout-redirect-fx
 (fn [{:keys [then-fn
              catch-fn]}]
   (cond-> (.signoutRedirect @user-manager)
     catch-fn (.catch catch-fn)
     then-fn (.then then-fn))))

(re-frame/reg-event-db
 ::user-loaded
 (fn [db [_ js-user]]
   (let [id-token (.-id_token js-user)
         access-token (.-access_token js-user)
         expires-at (.-expires_at js-user)
         refresh-token (.-refresh_token js-user)
         token-type (.-token_type js-user)
         state (.-state js-user)
         session-state (.-session_state js-user)
         scope (.-scope js-user)
         profile (js->clj (.-profile js-user))]
     (assoc db
            ::status :loaded
            ::user
            {:id-token id-token
             :access-token access-token
             :refresh-token refresh-token
             :expires-at expires-at
             :token-type token-type
             :state state
             :scope scope
             :session-state session-state
             :profile profile}))))

(re-frame/reg-event-db
 ::user-unloaded
 (fn [db _]
   (-> db
       (dissoc ::user)
       (assoc ::status :unloaded))))

(re-frame/reg-event-fx
 ::silent-renew-error
 (fn [_ [_ err]]
   {:fx [[:dispatch [::user-unloaded]]]}))

;; "Public" API

(re-frame/reg-event-fx
 ::init
 (fn [{{:keys [status]
        :as db} :db} [_ config]]
   (if status
     {}
     {:db (assoc db ::status :init)
      ::init-fx {:config config
                 ;; :auto-login true
                 :after-login-callback
                 (fn [_]
                   (println "login callback complete"))
                 :catch-login-callback
                 (fn [error]
                   (.error js/console "login callback error" error))
                 :after-logout-callback
                 (fn [_]
                   (println "logout callback complete"))
                 :catch-logout-callback
                 (fn [error]
                   (.error js/console "logout callback error" error))}})))

(re-frame/reg-event-fx
 ::log-in
 (fn [{:keys [db]} _]
   (if-not (= :loaded (::status db))
     {::signin-redirect-fx {:then-fn #(println "signin redirect complete")}}
     {})))

(re-frame/reg-event-fx
 ::log-out
 (fn [{:keys [db]} _]
   (if (= :loaded (::status db))
     {::signout-redirect-fx {:then-fn #(println "signout redirect complete")}}
     {})))

;; Subs
(re-frame/reg-sub
 ::status
 (fn [db _]
   (::status db)))

(re-frame/reg-sub
 ::user
 (fn [db _]
   (::user db)))

(re-frame/reg-sub
 ::logged-in?
 (fn [_ _]
   (re-frame/subscribe [::status]))
 (fn [status _]
   (= :loaded
      status)))
