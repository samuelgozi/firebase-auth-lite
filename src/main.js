/**
 * Full documentation for the "identitytoolkit" API can be found here:
 * https://developers.google.com/resources/api-libraries/documentation/identitytoolkit/v3/python/latest/identitytoolkit_v3.relyingparty.html
 */
import humanReadableErrors from './errors.json';

/**
 * Handles errors and converts the
 * response into an object and returns it.
 *
 * @prop {Response} response The raw response returned from the fetch API.
 * @returns {Object} response data.
 * @private
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
 * @private
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
 * Encapsulates authentication flow logic.
 * @param {Object} options Options object.
 * @param {string} options.apiKey The firebase API key
 * @param {string} options.redirectUri The redirect URL used by OAuth providers.
 * @param {Array.<ProviderOptions|string>} options.providers Array of arguments that will be passed to the addProvider method.
 */
export default class Auth {
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

	/**
	 * Verifies that the user is logged in,
	 * If not then he can't run the method that called this function.
	 * @private
	 */
	verifyLoggedIn() {
		if (!this.user) throw Error('The user must be logged-in to use this method.');
	}

	/**
	 * Saves the user data in the local storage.
	 * @param {Object} credentials
	 * @private
	 */
	persistSession(userData) {
		// Persist the session to the local storage.
		localStorage.setItem(`Auth:User:${this.apiKey}`, JSON.stringify(userData));
		this.user = userData;
	}

	/**
	 * Sign out the currently signed in user.
	 * Removes all data stored in the localStorage that's associated with the user.
	 */
	signOut() {
		localStorage.removeItem(`Auth:User:${this.apiKey}`);
		this.user = null;
	}

	/**
	 * Refreshes the idToken by using the locally stored refresh token
	 * only if the idToken has expired.
	 * @private
	 */
	async refreshIdToken() {
		// If the idToken didn't expire, return.
		if (Date.now() < this.user.tokenManager.expiresAt) return;

		// If a request for a new token was already made, then wait for it and then return.
		if (this.refreshTokenRequest) {
			console.log('Already called...');
			return await this.refreshTokenRequest;
		}

		try {
			// Calculated expiration time for the new token.
			const expiresAt = Date.now() + 3600 * 1000;

			// Save the promise so that if this function is called
			// anywhere else we don't make more than one request.
			this.refreshTokenRequest = fetch(this.endpoints.token, {
				method: 'POST',
				body: JSON.stringify({
					grant_type: 'refresh_token',
					refresh_token: this.user.tokenManager.refreshToken
				})
			})
				.then(handleIdentityToolkitResponse)
				.then(({ id_token: idToken, refresh_token: refreshToken }) => {
					// Merge the new data with the old data and save it locally.
					this.persistSession({
						...this.user,
						// Rename the data names to match the ones used in the app.
						tokenManager: { idToken, refreshToken, expiresAt }
					});
				});
		} catch (e) {
			this.refreshTokenRequest = null;
			throw e;
		}
	}

	/**
	 * Uses native fetch, but adds authorization headers
	 * The API is exactly the same as native fetch.
	 * @param {Request|Object|string} resource the resource to send the request to, or an options object.
	 * @param {Object} init an options object.
	 */
	async authorizedRequest(resource, init) {
		const request = resource instanceof Request ? resource : new Request(resource, init);

		if (this.user !== null) {
			// Check if the token expired. If it did, refresh it.
			if (Date.now() > this.user.tokenManager.expiresAt) await this.refreshIdToken();
			request.headers.set('Authorization', `Bearer ${this.user.tokenManager.idToken}`);
		}

		return fetch(request);
	}

	/**
	 * Start auth flow of a federated id provider.
	 * Will redirect the page to the federated login page.
	 * @param {string} providerName A valid provider name
	 * @param {string} [localRedirectUri] The url to redirect back to after the authorization is done.
	 */
	async startOauthFlow(providerName, localRedirectUri) {
		// Get an array of the allowed providers names.
		const allowedProviders = Object.keys(this.providers);

		// Verify that the requested provider is indeed configured.
		if (!allowedProviders.includes(providerName))
			throw Error(`You haven't configured "${providerName}" with this AuthFlow instance.`);

		try {
			// Get the url and other data necessary for the authentication.
			const { authUri, sessionId } = await this.providers[providerName].getAuthUri();

			// If the argument redirectUri was passed, then save it in sessionStorage.
			// This is not the redirectUri sent to the Provider, this is an internal redirectUri
			// used for routing within the app after the Authorization was performed.
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
		// Calculate the expiration date for the idToken.
		const expiresAt = Date.now() + 3600 * 1000;

		// Try to exchange the Auth Code for an idToken and refreshToken.
		const { idToken, refreshToken } = await fetch(this.endpoints.signInWithIdp, {
			method: 'POST',
			body: JSON.stringify({
				requestUri: responseUrl,
				sessionId,
				returnIdpCredential: true,
				returnSecureToken: true
			})
		}).then(handleIdentityToolkitResponse);

		// We don't rely on the returned data because it contains information
		// that is only accessible by issuing requests directly to the federated
		// id provider.
		//
		// That data is is still available if you request it explicitly,
		// but that is out of the scope of this library because its not required by all apps,
		// and it is also the way the official SDK handles(ignores) this data.
		//
		// Instead we will make another request to the Firebase API to request the data
		// that it saves, and therefore can be kept updated easily. And trust me, I don't
		// like making additional requests either.
		this.getProfile({ idToken, refreshToken, expiresAt });

		// Now clean up the temporary objects from the local storage.
		// This includes the sessionId and the local redirectURI.
		sessionStorage.removeItem(`Auth:Redirect:${this.apiKey}`);
		sessionStorage.removeItem(`Auth:SessionId:${this.apiKey}`);

		// If a local redirect uri was set, redirect to it
		// else, just get rid of the params in the location bar.
		location.href = redirectUri || location.origin + location.pathname;
	}

	/**
	 * Gets the user data from the server, and updates the local caches.
	 * @param {Object} [tokenManager] Only when not logged in.
	 * @returns {Object}
	 */
	async getProfile(tokenManager = this.user || this.user.tokenManager) {
		this.verifyLoggedIn();
		this.refreshIdToken();

		const userData = (
			await fetch(this.endpoints.lookup, {
				method: 'POST',
				body: `{"idToken":"${tokenManager.idToken}"}`
			}).then(handleIdentityToolkitResponse)
		).users[0];

		delete userData.kind;
		userData.tokenManager = tokenManager;

		this.persistSession(userData);
		return userData;
	}

	/**
	 * Signs up with email and password or anonymously when passed no arguments.
	 * Signs the user in automatically on completion.
	 * @param {string} [email] The email for the user to create.
	 * @param {string} [password] The password for the user to create.
	 */
	async signUp(email, password) {
		// Calculate the expiration date for the idToken.
		const expiresAt = Date.now() + 3600 * 1000;
		const { idToken, refreshToken } = await fetch(this.endpoints.signUp, {
			method: 'POST',
			body: JSON.stringify({
				email,
				password,
				returnSecureToken: true
			})
		}).then(handleIdentityToolkitResponse);

		// Get the user profile and persists the session.
		await this.getProfile({ idToken, refreshToken, expiresAt });
	}

	/**
	 * Sign in with email and password.
	 * @param {string} email
	 * @param {string} password
	 */
	async signInWithPassword(email, password) {
		// Calculate the expiration date for the idToken.
		const expiresAt = Date.now() + 3600 * 1000;
		const { idToken, refreshToken } = await fetch(this.endpoints.signInWithPassword, {
			method: 'POST',
			body: JSON.stringify({
				email,
				password,
				returnSecureToken: true
			})
		}).then(handleIdentityToolkitResponse);

		// Get the user profile and persists the session.
		await this.getProfile({ idToken, refreshToken, expiresAt });
	}

	/**
	 * Send a password reset code to the user's email.
	 */
	async sendPasswordResetCode(email) {
		await fetch(this.endpoints.sendOobCode, {
			method: 'POST',
			body: `{"requestType": "PASSWORD_RESET", "email": "${email}" }`
		}).then(handleIdentityToolkitResponse);
	}

	/**
	 * Sets a new password by using a reset code.
	 * @param {string} code
	 */
	verifyPasswordResetCode(code) {
		return fetch(this.endpoints.resetPassword, {
			method: 'POST',
			body: `{"oobCode": "${code}"}`
		}).then(handleIdentityToolkitResponse);
	}

	/**
	 * Sets a new password by using a reset code.
	 * Can also be used to very oobCode by not passing a password.
	 * @param {string} code
	 * @returns {string} The email of the account to which the code was issued.
	 */
	async resetPassword(oobCode, newPassword) {
		const { email } = await fetch(this.endpoints.resetPassword, {
			method: 'POST',
			body: JSON.stringify({ oobCode, newPassword })
		}).then(handleIdentityToolkitResponse);

		return email;
	}

	/**
	 * Update user's profile information.
	 */
	async updateProfile(newData) {
		this.verifyLoggedIn();
		this.refreshIdToken();

		// Calculate the expiration date for the idToken.
		const expiresAt = Date.now() + 3600 * 1000;
		const updatedData = await fetch(this.endpoints.update, {
			method: 'POST',
			body: JSON.stringify({
				...newData,
				idToken: this.user.tokenManager.idToken,
				returnSecureToken: true
			})
		}).then(handleIdentityToolkitResponse);

		if (updatedData.idToken) {
			updatedData.tokenManager = {
				idToken: updatedData.idToken,
				refreshToken: updatedData.refreshToken,
				expiresAt
			};
		} else {
			updatedData.tokenManager = this.user.tokenManager;
		}

		delete updatedData.kind;
		delete updatedData.idToken;
		delete updatedData.refreshToken;

		this.persistSession(updatedData);
	}

	async deleteAccount() {
		this.verifyLoggedIn();
		this.refreshIdToken();

		await fetch(this.endpoints.delete, {
			method: 'POST',
			body: `{"idToken": "${this.user.tokenManager.idToken}"}`
		}).then(handleIdentityToolkitResponse);

		this.signOut();
	}
}