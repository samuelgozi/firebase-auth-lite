/**
 * Full documentation for the "identitytoolkit" API can be found here:
 * https://developers.google.com/resources/api-libraries/documentation/identitytoolkit/v3/python/latest/identitytoolkit_v3.relyingparty.html
 */
import humanReadableErrors from './errors';

/**
 * Handles errors and converts the
 * response into an object and returns it.
 *
 * @prop {Response} response The raw response returned from the fetch API.
 * @returns {Object} response data.
 */
async function handleIdentityToolkitResponse(response) {
	const data = await response.json();

	// If the response has an error, check to see if we have a human readable version of it,
	// and throw that instead.
	if (!response.ok) {
		throw Error(humanReadableErrors[data.error.message] || data.error.message);
	}

	return data;
}

/**
 * Allowed types for the "from" option.
 * @typedef {Object} ProviderOptions
 * @prop {string} provider The lower-cased name of the provider(google/facebook/etc).
 * @prop {string} redirectUri Uri to redirect to with the access_token.
 * @prop {string} [customParams] Custom params for the request.
 * @prop {string} [scope] Scope string for the federated provider.
 * @prop {string} endpoint A Url endpoint for a custom provider.
 */

/**
 * Encapsulates Federated identity configuration and logic.
 * @prop {ProviderOptions} options
 */
class Provider {
	constructor({ provider, redirectUri, customParams, scope, endpoint }) {
		const allowedProviders = ['google', 'facebook', 'github', 'twitter'];
		const defaultScopes = {
			google: 'profile',
			facebook: 'email'
		};

		// Validate the name.
		if (!allowedProviders.includes(provider))
			throw Error(
				`"${provider}" Is not a valid provider name, The supported providers are "${allowedProviders.join(', ')}"`
			);

		// Validate that required params are not undefined.
		if (redirectUri === undefined)
			throw Error('Provider requires the "redirectUri" prop in order to create an instance.');

		if (endpoint === undefined) throw Error('Provider requires the "redirectUri" prop in order to create an instance.');

		this.endpoint = endpoint;
		this.provider = provider;
		this.redirectUri = redirectUri;
		this.customParams = customParams;
		this.scope = scope || defaultScopes[provider];
	}

	/**
	 * Returns the authentication endpoint URI for the
	 * federated provider with all the required settings
	 * to proceed with the authentication.
	 */
	getAuthUri() {
		return fetch(this.endpoint, {
			method: 'POST',
			body: JSON.stringify({
				providerId: this.provider + '.com',
				continueUri: this.redirectUri,
				oauthScope: this.scope,
				customParameter: this.customParams
			})
		}).then(handleIdentityToolkitResponse);
	}
}

/**
 * Encapsulates authentication logic.
 * @param {Object} options Options object.
 * @param {string} options.apiKey The firebase API key
 * @param {string} options.redirectUri The URL to redirect to after signIn.
 * @param {Array.<ProviderOptions|string>} options.providers Array of arguments that will be passed to the addProvider method.
 */
export class AuthFlow {
	constructor({ apiKey, redirectUri, providers }) {
		if (!redirectUri) throw Error('The argument "redirectUri" is required');

		function getEndpoint(path) {
			return `https://identitytoolkit.googleapis.com/v1/accounts:${path}?key=${apiKey}`;
		}

		this.apiKey = apiKey;
		this.redirectUri = redirectUri;
		this.providers = {};
		this.endpoints = {
			token: `https://securetoken.googleapis.com/v1/token?key=${apiKey}`,
			signUp: getEndpoint('signUp'),
			signInWithCustomToken: getEndpoint('signInWithCustomToken'),
			signInWithPassword: getEndpoint('signInWithPassword'),
			signInWithIdp: getEndpoint('signInWithIdp'),
			createAuthUri: getEndpoint('createAuthUri'),
			sendOobCode: getEndpoint('sendOobCode'),
			resetPassword: getEndpoint('resetPassword'),
			update: getEndpoint('update'),
			lookup: getEndpoint('lookup'),
			delete: getEndpoint('delete')
		};

		if (providers) {
			if (!Array.isArray(providers)) throw Error('The argument "providers" should be an array');
			providers.forEach(options => this.addProvider(options));
		}

		// If the user is already logged, then it will be his data, else it'll be null.
		this.user = JSON.parse(localStorage.getItem(`Auth:User:${this.apiKey}`));
	}

	// Saves the credentials along with the access token and id token in localStorage.
	persistSession(credentials) {
		localStorage.setItem(`Auth:User:${this.apiKey}`, JSON.stringify(credentials));
		this.user = credentials;
	}

	// Remove the session info from the localStorage.
	signOut() {
		localStorage.removeItem(`Auth:User:${this.apiKey}`);
		this.user = null;
	}

	/**
	 * Uses native fetch, but adds authorization headers
	 * if the Reference was instantiated with an auth instance.
	 * The API is exactly the same as native fetch.
	 * @param {Request|Object|string} resource the resource to send the request to, or an options object.
	 * @param {Object} init an options object.
	 */
	async authorizedRequest(resource, init) {
		const request = resource instanceof Request ? resource : new Request(resource, init);

		if (this.user !== null) {
			// If the token already expired,
			// then refresh it and only after that add authorization headers.
			if (this.user.expiresAt < Date.now()) await this.refreshIdToken();
			request.headers.set('Authorization', `Bearer ${this.user.idToken}`);
		}

		return fetch(request);
	}

	// Exchange a refresh token for an id token.
	async refreshIdToken() {
		const response = await fetch(this.endpoints.token, {
			method: 'POST',
			body: JSON.stringify({
				grant_type: 'refresh_token',
				refresh_token: this.user.refreshToken
			})
		}).then(handleIdentityToolkitResponse);

		// Merge the new data with the old data and save it locally.
		this.persistSession({
			...this.user,

			// Rename the data names to match the ones used in the app.
			oauthAccessToken: response.access_token,
			idToken: response.id_token,
			refreshToken: response.refresh_token,
			expiresAt: Date.now() + response.expires_in * 1000
		});
	}

	/**
	 * Adds a provider to the AuthFlow instance.
	 * @param {(ProviderOptions|string)} options Can be an options object, or a string representing the name of a provider.
	 */
	addProvider(options) {
		if (typeof options === 'string') options = { provider: options };
		this.providers[options.provider] = new Provider({
			redirectUri: this.redirectUri,
			endpoint: this.endpoints.createAuthUri,
			...options
		});
	}

	// Start auth flow of a federated id provider.
	async startOauthFlow(providerName, localRedirectUri) {
		// Get an array of the allowed providers names.
		const allowedProviders = Object.keys(this.providers);

		// Verify that the requested provider is indeed configured.
		if (!allowedProviders.includes(providerName))
			throw Error(`"${providerName}" is not configured in this instance AuthFlow`);

		try {
			// Get the url and other data necessary for the authentication.
			const { authUri, sessionId } = await this.providers[providerName].getAuthUri();

			// If the argument redirectUri was passed, then save it in sessionStorage.
			// This is not the redirectUri sent to the Provider, this is an internal redirectUri
			// used internally for routing within the app after the Authorization was performed.
			if (localRedirectUri) sessionStorage.setItem(`Auth:Redirect:${this.apiKey}`, localRedirectUri);
			// Save the sessionId that we just received in the local storage.
			sessionStorage.setItem(`Auth:SessionId:${this.apiKey}`, sessionId);

			// Finally - redirect the page to the auth endpoint.
			location.href = authUri;
		} catch (error) {
			// If it failed to initialize the Auth flow for any reason,
			// remove all the temporary objects from the sessionStorage.
			sessionStorage.removeItem(`Auth:Redirect:${this.apiKey}`);
			sessionStorage.removeItem(`Auth:SessionId:${this.apiKey}`);

			// Throw the error.
			throw error;
		}
	}

	/**
	 * This code runs after the Federated Id Provider
	 * returned the auth Code to our page, and exchanges it with
	 * User info, Access Token and ID token.
	 */
	async finishOauthFlow(responseUrl = location.href) {
		// Get the local redirect URI if it exists.
		const redirectUri = sessionStorage.getItem(`Auth:Redirect:${this.apiKey}`);
		// Get the sessionId we received before the redirect from sessionStorage.
		const sessionId = sessionStorage.getItem(`Auth:SessionId:${this.apiKey}`);

		// Try to exchange the Auth Code for Token and user
		// data and save the data to the local storage.
		const userData = await fetch(this.endpoints.signInWithIdp, {
			method: 'POST',
			body: JSON.stringify({
				requestUri: responseUrl,
				sessionId,
				returnIdpCredential: true,
				returnSecureToken: true
			})
		}).then(handleIdentityToolkitResponse);

		this.persistSession({
			...userData,
			// Add timestamp for the expiration date of the object.
			expiresAt: Date.now() + userData.expiresIn * 1000
		});

		// Now clean up the temporary objects from the local storage.
		// This includes the sessionId and the local redirectURI.
		sessionStorage.removeItem(`Auth:Redirect:${this.apiKey}`);
		sessionStorage.removeItem(`Auth:SessionId:${this.apiKey}`);

		// If a local redirect uri was set, redirect to it
		// else, just get rid of the params in the location bar.
		location.href = redirectUri || location.origin + location.pathname;
	}
}
