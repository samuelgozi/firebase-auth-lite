import humanReadableErrors from './errors.json';
const localStorageAdapter = {
    getItem: async (key) => {
        return await localStorage.getItem(key);
    },
    removeItem: async (key) => {
        return await localStorage.removeItem(key);
    },
    setItem: async (key, value) => {
        return await localStorage.setItem(key, value);
    },
};
/**
 * Settings object for an IDP(Identity Provider).
 * @typedef {Object} ProviderOptions
 * @property {string} options.name The name of the provider in lowercase.
 * @property {string} [options.scope] The scopes for the IDP, this is optional and defaults to "openid email".
 */
/**
 * Object response from a "fetchProvidersForEmail" request.
 * @typedef {Object} ProvidersForEmailResponse
 * @property {Array.<string>} allProviders All providers the user has once used to do federated login
 * @property {boolean} registered All sign-in methods this user has used.
 * @property {string} sessionId Session ID which should be passed in the following verifyAssertion request
 * @property {Array.<string>} signinMethods All sign-in methods this user has used.
 */
/**
 * Setting object for the "startOauthFlow" method.
 * @typedef {Object} oauthFlowOptions
 * @property {string} provider Name of the provider to use.
 * @property {string} [context] A string that will be returned after the Oauth flow is finished, should be used to retain context.
 * @property {boolean} [linkAccount = false] Whether to link this oauth account with the current account. defaults to false.
 */
/**
 * Encapsulates authentication flow logic.
 * @param {Object} options Options object.
 * @param {string} options.apiKey The firebase API key
 * @param {string} options.redirectUri The redirect URL used by OAuth providers.
 * @param {Array.<ProviderOptions|string>} options.providers Array of arguments that will be passed to the addProvider method.
 */
export default class Auth {
    constructor({ name = 'default', apiKey, redirectUri, providers = [], storage = localStorageAdapter, lazyInit }) {
        this.refreshTokenRequest = null;
        this.initialized = false;
        if (!apiKey)
            throw Error('The argument "apiKey" is required');
        if (!Array.isArray(providers))
            throw Error('The argument "providers" must be an array');
        /**
         * Event listener's callbacks.
         * @private
         */
        this.listeners = [];
        this.storage = storage;
        this.user = null;
        Object.assign(this, {
            name,
            apiKey,
            redirectUri,
            providers: {}
        });
        for (let options of providers) {
            const { name, scope } = typeof options === 'string' ? { name: options, scope: undefined } : options;
            this.providers[name] = scope;
        }
        if (!lazyInit) {
            this.initUser();
        }
    }
    async initUser() {
        /**
         * User data if the user is logged in, else its null.
         * @type {Object|null}
         */
        const storedUser = await this.storage.getItem(`Auth:User:${this.apiKey}:${this.name}`);
        this.user = storedUser ? JSON.parse(storedUser) : null;
        if (this.user) {
            await this.refreshIdToken();
        }
        this.initialized = true;
        this.emit();
        if (this.user) {
            await this.fetchProfile();
        }
    }
    get currentUser() {
        return this.user;
    }
    /**
     * Emits an event and triggers all of the listeners.
     * @param {string} name The name of the event to trigger.
     * @param {any} data The data you want to pass to the event listeners.
     * @private
     */
    emit() {
        this.listeners.forEach(cb => cb(this.user));
    }
    /**
     * Set up a function that will be called whenever the user state is changed.
     * @param {function} cb The function to call when the event is triggered.
     */
    onAuthStateChanged(cb) {
        this.listeners.push(cb);
        if (this.initialized) {
            cb(this.user);
        }
        // Return a function to unbind the callback.
        return () => (this.listeners = this.listeners.filter(fn => fn !== cb));
    }
    /**
     * Make post request to a specific endpoint, and return the response.
     * @param {string} endpoint The name of the endpoint.
     * @param {any} request Body to pass to the request.
     * @private
     */
    api(endpoint, body) {
        const url = endpoint === 'token'
            ? `https://securetoken.googleapis.com/v1/token?key=${this.apiKey}`
            : `https://identitytoolkit.googleapis.com/v1/accounts:${endpoint}?key=${this.apiKey}`;
        return fetch(url, {
            method: 'POST',
            body: typeof body === 'string' ? body : JSON.stringify(body)
        }).then(async (response) => {
            const data = await response.json();
            // If the response has an error, check to see if we have a human readable version of it,
            // and throw that instead.
            if (!response.ok) {
                const error = Error(humanReadableErrors[data.error.message] || data.error.message);
                error.code = data.error.message;
                throw error;
            }
            return data;
        });
    }
    /**
     * Makes sure the user is logged in and has up-to-date credentials.
     * @throws Will throw if the user is not logged in.
     * @private
     */
    enforceAuth() {
        if (!this.user)
            throw Error('The user must be logged-in to use this method.');
        return this.refreshIdToken(); // Won't do anything if the token is valid.
    }
    /**
     * Saves the user data in the local storage.
     * @param {Object} credentials
     * @private
     */
    async persistSession(userData) {
        // Persist the session to the local storage.
        await this.storage.setItem(`Auth:User:${this.apiKey}:${this.name}`, JSON.stringify(userData));
        this.user = userData;
        this.emit();
    }
    /**
     * Sign out the currently signed in user.
     * Removes all data stored in the storage that's associated with the user.
     */
    async signOut() {
        await this.storage.removeItem(`Auth:User:${this.apiKey}:${this.name}`);
        this.user = null;
        this.emit();
    }
    /**
     * Refreshes the idToken by using the locally stored refresh token
     * only if the idToken has expired.
     * @private
     */
    async refreshIdToken(forceRefresh) {
        var _a, _b, _c;
        // If the idToken didn't expire, return.
        if (!forceRefresh && Date.now() < ((_b = (_a = this.user) === null || _a === void 0 ? void 0 : _a.tokenManager.expiresAt) !== null && _b !== void 0 ? _b : 0))
            return;
        // If a request for a new token was already made, then wait for it and then return.
        if (this.refreshTokenRequest) {
            return await this.refreshTokenRequest;
        }
        try {
            // Calculated expiration time for the new token.
            const expiresAt = Date.now() + 3600 * 1000;
            // Save the promise so that if this function is called
            // anywhere else we don't make more than one request.
            this.refreshTokenRequest = this.api('token', {
                grant_type: 'refresh_token',
                refresh_token: (_c = this.user) === null || _c === void 0 ? void 0 : _c.tokenManager.refreshToken
            }).then(({ id_token: idToken, refresh_token: refreshToken }) => {
                // Merge the new data with the old data and save it locally.
                return this.persistSession({
                    ...this.user,
                    // Rename the data names to match the ones used in the app.
                    tokenManager: { idToken, refreshToken, expiresAt }
                });
            });
        }
        catch (e) {
            this.refreshTokenRequest = null;
            throw e;
        }
        return this.refreshTokenRequest;
    }
    /**
     * Uses native fetch, but adds authorization headers otherwise the API is exactly the same as native fetch.
     * @param {Request|Object|string} resource the resource to send the request to, or an options object.
     * @param {Object} init an options object.
     */
    async authorizedRequest(resource, init) {
        const request = resource instanceof Request ? resource : new Request(resource, init);
        if (this.user !== null) {
            await this.refreshIdToken(); // Won't do anything if the token didn't expire yet.
            request.headers.set('Authorization', `Bearer ${this.user.tokenManager.idToken}`);
        }
        return fetch(request);
    }
    /**
     * Signs in or signs up a user by exchanging a custom Auth token.
     * @param {string} token The custom token.
     */
    async signInWithCustomToken(token) {
        // Calculate the expiration date for the idToken.
        const expiresAt = Date.now() + 3600 * 1000;
        // Try to exchange the Auth Code for an idToken and refreshToken.
        const { idToken, refreshToken } = await this.api('signInWithCustomToken', { token, returnSecureToken: true });
        // Now get the user profile.
        await this.fetchProfile({ idToken, refreshToken, expiresAt });
    }
    /**
     * Signs up with email and password or anonymously when no arguments are passed.
     * Automatically signs the user in on completion.
     * @param {string} [email] The email for the user to create.
     * @param {string} [password] The password for the user to create.
     */
    async signUp(email, password) {
        // Calculate the expiration date for the idToken.
        const expiresAt = Date.now() + 3600 * 1000;
        const { idToken, refreshToken } = await this.api('signUp', {
            email,
            password,
            returnSecureToken: true
        });
        // Get the user profile and persists the session.
        await this.fetchProfile({ idToken, refreshToken, expiresAt });
    }
    /**
     * Signs in a user with email and password.
     * @param {string} email
     * @param {string} password
     */
    async signIn(email, password) {
        // Calculate the expiration date for the idToken.
        const expiresAt = Date.now() + 3600 * 1000;
        const { idToken, refreshToken } = await this.api('signInWithPassword', {
            email,
            password,
            returnSecureToken: true
        });
        // Get the user profile and persists the session.
        await this.fetchProfile({ idToken, refreshToken, expiresAt });
    }
    /**
     * Gets the user data from the server, and updates the local caches.
     * @param {Object} [tokenManager] Only when not logged in.
     * @throws Will throw if the user is not signed in.
     */
    async fetchProfile(tokenManager = this.user && this.user.tokenManager) {
        !this.user && !tokenManager && (await this.enforceAuth());
        const userData = (await this.api('lookup', { idToken: tokenManager === null || tokenManager === void 0 ? void 0 : tokenManager.idToken })).users[0];
        delete userData.kind;
        userData.tokenManager = tokenManager;
        await this.persistSession(userData);
    }
}
