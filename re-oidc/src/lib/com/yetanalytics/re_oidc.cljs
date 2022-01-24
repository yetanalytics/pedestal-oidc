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

(s/def :com.yetanalytics.re-oidc.error/name string?)
(s/def :com.yetanalytics.re-oidc.error/message string?)
(s/def :com.yetanalytics.re-oidc.error/handler qualified-keyword?)
(s/def :com.yetanalytics.re-oidc.error/ex-data qualified-keyword?)

(s/def ::error
  (s/keys :req-un [:com.yetanalytics.re-oidc.error/name
                   :com.yetanalytics.re-oidc.error/message
                   :com.yetanalytics.re-oidc.error/handler]
          :opt-un [:com.yetanalytics.re-oidc.error/ex-data]))

(s/def ::errors (s/every ::error))

;; A (partial) spec for what re-oidc puts in the re-frame db
(def partial-db-spec
  (s/keys :opt [::status
                ::user
                ::callback
                ::login-query-string
                ::errors]))

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
     (dispatch-cb [::access-token-expiring]))
    (.addAccessTokenExpired
     (dispatch-cb [::access-token-expired]))
    (.addSilentRenewError
     (dispatch-cb [::silent-renew-error]))
    ;; session monitoring requires an iframe
    ;; this breaks Figwheel and makes dev hard
    ;; TODO: enable on-demand for those with iframe-friendly idp settings
    #_(.addUserSignedIn
     (dispatch-cb [::user-signed-in]))
    #_(.addUserSignedOut
     (dispatch-cb [::user-signed-out]))
    #_(.addUserSessionChanged
     (dispatch-cb [::user-session-changed]))))

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
 (fn [{:keys [config]}]
   (swap! user-manager init! config)))

(defn- throw-not-initialized!
  []
  (throw (ex-info "UserManager not Initialized!"
                  {:type ::user-manager-not-initialized})))

(defn- get-user-manager
  []
  (if-some [user-manager @user-manager]
    user-manager
    (throw-not-initialized!)))

(re-frame/reg-fx
 ::get-user-fx
 (fn [{:keys [on-success
              on-failure]}]
   (let [on-failure (or on-failure
                        [::add-error ::get-user-fx])]
     (-> (get-user-manager)
         .getUser
         (handle-promise on-success on-failure)))))

(re-frame/reg-fx
 ::signin-redirect-fx
 (fn [{:keys [on-success
              on-failure]}]
   (let [on-failure (or on-failure
                        [::add-error ::signin-redirect-fx])]
     (-> (get-user-manager)
         .signinRedirect
         (handle-promise on-success on-failure)))))

(re-frame/reg-fx
 ::signin-redirect-callback-fx
 (fn [{:keys [on-success
              on-failure
              query-string]}]
   (let [on-failure (or on-failure
                        [::add-error ::signin-redirect-callback-fx])
         um (get-user-manager)]
     (-> um
         (.signinRedirectCallback query-string)
         (handle-promise on-success on-failure)
         (.then #(.clearStaleState um))))))

(re-frame/reg-fx
 ::signout-redirect-fx
 (fn [{:keys [on-success
              on-failure]}]
   (let [on-failure (or on-failure
                        [::add-error ::signout-redirect-fx])]
     (-> (get-user-manager)
         .signoutRedirect
         (handle-promise on-success on-failure)))))

(re-frame/reg-fx
 ::signout-redirect-callback-fx
 (fn [{:keys [on-success
              on-failure]}]
   (let [on-failure (or on-failure
                        [::add-error ::signout-redirect-callback-fx])]
     (-> (get-user-manager)
         .signoutRedirectCallback
         (handle-promise on-success on-failure)))))

(defn- js-error->clj
  [handler-id js-error]
  (let [?exd (ex-data js-error)]
    (cond-> {:name (.-name js-error)
             :message (ex-message js-error)
             :handler handler-id}
      ?exd (assoc :ex-data ?exd))))

(re-frame/reg-event-db
 ::add-error
 (fn [db [_ handler-id js-error]]
   (update db
           :errors
           (fnil conj [])
           (js-error->clj
            handler-id
            js-error))))

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

(re-frame/reg-event-fx
 ::access-token-expired
 (fn [_ [_ err]]
   {:fx [[:dispatch [::user-unloaded]]]}))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; "Public" API ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; (maybe) Pre-initialization events

;; Add login redirect callback state, usually from routing
(re-frame/reg-event-fx
 ::login-callback
 (fn [{{?status ::status
        :as db} :db} [_
                      qstring
                      {:keys [on-login-success
                              on-login-failure]}]]
   (cond
     ;; Pre-init
     (nil? ?status) {:db (assoc db
                                ::callback :login
                                ::login-query-string qstring)}
     (#{:init
        :unloaded}
      ?status) {:db db
                :fx [[::signin-redirect-callback-fx
                      {:query-string qstring
                       :on-success on-login-success
                       :on-failure on-login-failure}]]}
     :else
     (do
       (.warn js/console
              "::re-oidc/login-callback called with unknown status"
              (name ?status))
       {}))))

;; Add logout redirect callback state, usually from routing
(re-frame/reg-event-fx
 ::logout-callback
 (fn [{{?status ::status
        :as db} :db} [_
                      {:keys [on-logout-success
                              on-logout-failure]}]]
   (case ?status
     ;; Pre-init
     nil {:db (assoc db
                     ::callback :logout)}
     :init {:db db
            :fx [[::signout-redirect-callback-fx
                  {:on-success on-logout-success
                   :on-failure on-logout-failure}]]}
     (do
       (.warn js/console
              "::re-oidc/logout-callback called with unknown status"
              (name ?status))
       {}))))

(defn- expired?
  [expires-at]
  (< (* expires-at 1000) (.now js/Date)))

;; Initialization
;; Sets up the OIDC client from config and queues login/logout callback
;; Or if not on a callback, attempts to get the user from storage
(re-frame/reg-event-fx
 ::init
 (fn [{{:keys [status]
        ?callback ::callback
        ?qstring ::login-query-string
        :as db} :db} [_ {:keys [config
                                auto-login
                                on-login-success
                                on-login-failure
                                on-logout-success
                                on-logout-failure
                                on-get-user-success
                                on-get-user-failure]}]]
   (if status
     {}
     {:db (-> db
              (assoc ::status :init)
              (dissoc ::callback
                      ::login-query-string))
      :fx [[::init-fx
            {:config config}]
           (case ?callback
             :login [::signin-redirect-callback-fx
                     {:query-string ?qstring
                      :on-success on-login-success
                      :on-failure on-login-failure}]
             :logout [::signout-redirect-callback-fx
                      {:on-success on-logout-success
                       :on-failure on-logout-failure}]
             [::get-user-fx
              ;; We need to set the user, if present, no matter what
              {:on-success
               (cond-> (fn [?user]
                         (if-let [logged-in-user (and ?user
                                                      (not
                                                       (some-> ?user
                                                               .-expires_at
                                                               expired?))
                                                      ?user)]
                           (re-frame/dispatch [::user-loaded logged-in-user])
                           (when auto-login
                             (re-frame/dispatch [::login]))))
                 on-get-user-success
                 (juxt (cb-fn-or-dispatch on-get-user-success)))
               :on-failure on-get-user-failure}])]})))

;; Post-initialization

;; Get the UserManager for customization, if it is initialized
(re-frame/reg-cofx
 ::user-manager
 (fn [cofx _]
   (assoc cofx ::user-manager @user-manager)))

;; Trigger the login redirect from a user interaction
(re-frame/reg-event-fx
 ::login
 (fn [{:keys [db]} _]
   (if-not (= :loaded (::status db))
     {::signin-redirect-fx {}}
     {})))

;; Trigger the logout redirect from a user interaction
(re-frame/reg-event-fx
 ::logout
 (fn [{:keys [db]} _]
   (if (= :loaded (::status db))
     {::signout-redirect-fx {}}
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
 ::user/profile
 :<- [::user]
 (fn [user _]
   (:profile user)))

(re-frame/reg-sub
 ::logged-in?
 (fn [_ _]
   (re-frame/subscribe [::status]))
 (fn [status _]
   (= :loaded
      status)))
