/**
 * Full documentation for the "identitytoolkit" API can be found here:
 * https://cloud.google.com/identity-platform/docs/reference/rest/v1/accounts
 */
import { UserInfo as FBUser } from '@firebase/auth-types';
declare type User = FBUser & {
    tokenManager: {
        idToken: string;
        refreshToken: string;
        expiresAt: number;
    };
};
declare type UserCallback = (user: User | null) => void;
declare type Provider = {
    name: string;
    scope: unknown;
};
declare type AsyncStorage = {
    getItem: (key: string) => Promise<string | null>;
    removeItem: (key: string) => Promise<void>;
    setItem: (key: string, value: string) => Promise<void>;
};
declare type AuthOptions = {
    apiKey: string;
    lazyInit?: boolean;
    name?: string;
    providers?: Array<Provider | string>;
    redirectUri?: string;
    storage?: AsyncStorage;
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
    apiKey: string;
    listeners: UserCallback[];
    name: string;
    providers: Record<string, unknown>;
    redirectUri?: string;
    refreshTokenRequest: Promise<unknown> | null;
    user: User | null;
    storage: AsyncStorage;
    initialized: boolean;
    constructor({ name, apiKey, redirectUri, providers, storage, lazyInit }: AuthOptions);
    initUser(): Promise<void>;
    get currentUser(): User | null;
    /**
     * Emits an event and triggers all of the listeners.
     * @param {string} name The name of the event to trigger.
     * @param {any} data The data you want to pass to the event listeners.
     * @private
     */
    emit(): void;
    /**
     * Set up a function that will be called whenever the user state is changed.
     * @param {function} cb The function to call when the event is triggered.
     */
    onAuthStateChanged(cb: UserCallback): () => UserCallback[];
    /**
     * Make post request to a specific endpoint, and return the response.
     * @param {string} endpoint The name of the endpoint.
     * @param {any} request Body to pass to the request.
     * @private
     */
    api(endpoint: string, body: any): Promise<any>;
    /**
     * Makes sure the user is logged in and has up-to-date credentials.
     * @throws Will throw if the user is not logged in.
     * @private
     */
    enforceAuth(): Promise<unknown>;
    /**
     * Saves the user data in the local storage.
     * @param {Object} credentials
     * @private
     */
    persistSession(userData: User): Promise<void>;
    /**
     * Sign out the currently signed in user.
     * Removes all data stored in the storage that's associated with the user.
     */
    signOut(): Promise<void>;
    /**
     * Refreshes the idToken by using the locally stored refresh token
     * only if the idToken has expired.
     * @private
     */
    refreshIdToken(forceRefresh?: boolean): Promise<unknown>;
    /**
     * Uses native fetch, but adds authorization headers otherwise the API is exactly the same as native fetch.
     * @param {Request|Object|string} resource the resource to send the request to, or an options object.
     * @param {Object} init an options object.
     */
    authorizedRequest(resource: Request | RequestInfo | string, init: RequestInit): Promise<Response>;
    /**
     * Signs in or signs up a user by exchanging a custom Auth token.
     * @param {string} token The custom token.
     */
    signInWithCustomToken(token: string): Promise<void>;
    /**
     * Signs up with email and password or anonymously when no arguments are passed.
     * Automatically signs the user in on completion.
     * @param {string} [email] The email for the user to create.
     * @param {string} [password] The password for the user to create.
     */
    signUp(email: string, password: string): Promise<void>;
    /**
     * Signs in a user with email and password.
     * @param {string} email
     * @param {string} password
     */
    signIn(email: string, password: string): Promise<void>;
    /**
     * Gets the user data from the server, and updates the local caches.
     * @param {Object} [tokenManager] Only when not logged in.
     * @throws Will throw if the user is not signed in.
     */
    fetchProfile(tokenManager?: {
        idToken: string;
        refreshToken: string;
        expiresAt: number;
    } | null): Promise<void>;
}
export {};
