(ns com.yetanalytics.re-oidc
  (:require [cljsjs.oidc-client :refer [UserManager Log]]
            [re-frame.core :as re-frame]
            [clojure.spec.alpha :as s :include-macros true]
            [com.yetanalytics.re-oidc.user :as user]))

;; OIDC lib logging can be enabled:

#_(set! Log.logger js/console)

(s/def ::status #{:init :loaded :unloaded})
(s/def ::user user/user-spec)
(s/def ::callback #{:login :logout})
(s/def ::login-query-string string?)

;; A (partial) spec for what re-oidc puts in the re-frame db
(def partial-db-spec
  (s/keys :opt [::status
                ::user
                ::callback
                ::login-query-string]))

(defonce user-manager
  (atom nil))

(defn- dispatch-cb
  [qvec]
  (fn [& args]
    (re-frame/dispatch (into qvec args))))

(defn reg-events!
  "Register event callbacks to re-frame on the OIDC UserManager"
  [^UserManager user-manager]
  (doto user-manager.events
    (.addUserLoaded
     (dispatch-cb [::user-loaded]))
    (.addUserUnloaded
     (dispatch-cb [::user-unloaded]))
    ;; We set automaticSilentRenew to true and these are done for us
    #_(.addAccessTokenExpiring
     (dispatch-cb ::access-token-expiring))
    #_(.addAccessTokenExpired
     (dispatch-cb ::access-token-expired))
    (.addSilentRenewError
     (dispatch-cb [::silent-renew-error]))
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

(defn- cb-fn-or-dispatch
  [x]
  (cond
    (vector? x) (dispatch-cb x)
    (fn? x) x))

(defn- handle-promise
  "Handle a promise result from the lib"
  [p & [?on-success ?on-failure]]
  (cond-> p
    ?on-failure (.catch (cb-fn-or-dispatch ?on-failure))
    ?on-success (.then (cb-fn-or-dispatch ?on-success))))

(re-frame/reg-fx
 ::init-fx
 (fn [{:keys [config

              callback-type ;; nilable :login :logout
              login-query-string ;; Query String, REQUIRED for login

              auto-login

              after-login
              catch-login
              after-logout
              catch-logout]}]
   (let [manager (swap! user-manager init! config)]
     (case callback-type
       :login
       (-> manager
           (.signinRedirectCallback login-query-string)
           (handle-promise after-login catch-login))
       :logout
       (-> (.signoutRedirectCallback manager)
           (handle-promise after-logout catch-logout))
       ;; If a user is present, reflect in the db
       (-> manager
           .getUser
           (.then
            (fn [?user]
              (if ?user
                (re-frame/dispatch [::user-loaded ?user])
                (when auto-login
                  (re-frame/dispatch [::login]))))))))))

(re-frame/reg-fx
 ::signin-redirect-fx
 (fn [{:keys [then-fn
              catch-fn]}]
   (if-some [user-manager @user-manager]
     (handle-promise (.signinRedirect user-manager)
                     then-fn
                     catch-fn)
     (throw (ex-info "UserManager not Initialized!"
                     {:type ::user-manager-not-initialized})))))

(re-frame/reg-fx
 ::signout-redirect-fx
 (fn [{:keys [then-fn
              catch-fn]}]
   (if-some [user-manager @user-manager]
     (handle-promise (.signoutRedirect user-manager)
                     then-fn
                     catch-fn)
     (throw (ex-info "UserManager not Initialized!"
                     {:type ::user-manager-not-initialized})))))

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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; "Public" API ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Get the UserManager for customization
(re-frame/reg-cofx
 ::user-manager
 (fn [cofx _]
   (assoc cofx ::user-manager @user-manager)))

(re-frame/reg-event-fx
 ::login
 (fn [{:keys [db]} _]
   (if-not (= :loaded (::status db))
     {::signin-redirect-fx {:then-fn #(println "signin redirect complete")}}
     {})))

;; Set login callback key + qstring
(re-frame/reg-event-db
 ::login-callback
 (fn [db [_ qstring]]
   (if (::status db)
     (do
       (.warn js/console "::re-oidc/login-callback called after UserManager init, ignored")
       db)
     (assoc db
            ::callback :login
            ::login-query-string qstring))))


(re-frame/reg-event-fx
 ::logout
 (fn [{:keys [db]} _]
   (if (= :loaded (::status db))
     {::signout-redirect-fx {:then-fn #(println "signout redirect complete")}}
     {})))

;; Set logout callback key
(re-frame/reg-event-db
 ::logout-callback
 (fn [db _]
   (if (::status db)
     (do
       (.warn js/console "::re-oidc/logout-callback called after UserManager init, ignored")
       db)
     (assoc db
            ::callback :logout))))

;; Initialize the user manager
(re-frame/reg-event-fx
 ::init
 (fn [{{:keys [status]
        ?callback ::callback
        ?qstring ::login-query-string
        :as db} :db} [_ re-oidc-config]]
   (if status
     {}
     {:db (-> db
              (assoc ::status :init)
              (dissoc ::callback
                      ::login-query-string))
      ::init-fx
      (merge re-oidc-config
             (when ?callback
               {:callback-type ?callback})
             (when ?qstring
               {:login-query-string ?qstring}))})))


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
