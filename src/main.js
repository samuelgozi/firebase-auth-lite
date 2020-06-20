/**
 * Full documentation for the "identitytoolkit" API can be found here:
 * https://cloud.google.com/identity-platform/docs/reference/rest/v1/accounts
 */

import { localStorageAdapter } from './storage.js';

/**
 * Sets object for an IDP (Identity Provider).
 * @typedef {Object} ProviderOptions
 * @property {string} options.name Name of the provider in lowercase.
 * @property {string} [options.scope] Scopes for the IDP, this is optional and defaults to "OpenID email".
 */

/**
 * Object response from a "fetchProvidersForEmail" request.
 * @typedef {Object} ProvidersForEmailResponse
 * @property {Array.<string>} allProviders All providers the user has once used to do federated sign-in.
 * @property {boolean} registered All sign-in methods this user has used.
 * @property {string} sessionId Session ID which should be passed in the following verifyAssertion request.
 * @property {Array.<string>} signinMethods All sign-in methods this user has used.
 */

/**
 * Sets object for the "startOauthFlow" method.
 * @typedef {Object} oauthFlowOptions
 * @property {string} provider Name of the provider to use.
 * @property {string} [context] A string that will be returned after the OAuth flow is finished should be used to retain context.
 * @property {boolean} [linkAccount = false] Check whether to link this OAuth account with the current account. Defaults to false.
 */

/**
 * Encapsulates authentication flow logic.
 * @param {Object} options Options object.
 * @param {string} options.apiKey The Firebase API key.
 * @param {string} options.redirectUri The redirect URL used by OAuth providers.
 * @param {Array.<ProviderOptions|string>} options.providers Array of arguments that will be passed to the addProvider method.
 */
export default class Auth {
	constructor({
		apiKey,
		redirectUri,
		name = 'default',
		storage = localStorageAdapter,
	} = {}) {
		if (!apiKey) {
			throw Error('The argument "apiKey" is required');
		} else {
			Object.assign(this, {
				apiKey,
				redirectUri,
				name,
				storage,
				listeners: [],
			});

			this.storage.get(this.sKey('User')).then(user => {
				this.setState(JSON.parse(user), false);
				if (this.user) {
					this.refreshIdToken()
						.then(() => this.fetchProfile())
						.catch(error => {
							switch (error.message) {
								case 'TOKEN_EXPIRED':
								case 'INVALID_ID_TOKEN':
									return this.signOut();
								default:
									throw error;
							}
						});
				}
			});

			// Because this library is also used in React Native, outside the browser as well,
			// we need to check if this environment supports `addEventListener` on the window.
			if ('addEventListener' in window) {
				window.addEventListener('storage', event => {
					// This code runs if localStorage for this user
					// data is updated from a different browser window.
					if (event.key !== this.sKey('User')) {
						return;
					} else {
						this.setState(JSON.parse(event.newValue), false);
					}
				});
			}
		}
	}

	/**
	 * Emits an event and triggers all of the listeners.
	 * @param {string} name Name of the event to trigger.
	 * @param {any} data Data you want to pass to the event listeners.
	 * @private
	 */
	emit() {
		this.listeners.forEach(callback => callback(this.user));
	}

	/**
	 * Sets up a function that will be called whenever the user state is changed.
	 * @param {function} callback Function to call when the event is triggered.
	 * @returns {function} The function that unsubscribes your callback after being called.
	 */
	listen(callback) {
		this.listeners.push(callback);

		// Return a function to unbind the callback.
		return () => {
			this.listeners = this.listeners.filter(filter => filter !== callback);
		};
	}

	/**
	 * Generates a unique storage key for this app.
	 * @private
	 */
	sKey(key) {
		return `Auth:${key}:${this.apiKey}:${this.name}`;
	}

	/**
	 * Makes post request to a specific endpoint, and return the response.
	 * @param {string} endpoint Name of the endpoint.
	 * @param {any} request Body to pass to the request.
	 * @private
	 */
	async api(endpoint, body) {
		const url =
			endpoint === 'token'
				? `https://securetoken.googleapis.com/v1/token?key=${this.apiKey}`
				: `https://identitytoolkit.googleapis.com/v1/accounts:${endpoint}?key=${this.apiKey}`;

		const response = await fetch(url, {
			method: 'POST',
			body: typeof body === 'string' ? body : JSON.stringify(body),
		});
		let data = await response.json();
		// If the response returned an error, try to get a Firebase error code/message.
		// Sometimes the error codes are joined with an explanation, and we don't need that (it's a bug).
		// So we remove the unnecessary part.
		if (!response.ok) {
			const code = data.error.message.replace(/: [\w ,.'"()]+$/, '');
			throw Error(code);
		}

		// Calculate the expiration date for tokens.
		Object.defineProperty(data, 'expiresAt', {
			value: Date.parse(response.headers.get('date')) + 3600 * 1000,
		});

		return data;
	}

	/**
	 * Makes sure the user is signed-in and has up-to-date credentials.
	 * @throws Will throw if the user is not signed-in.
	 * @private
	 */
	async enforceAuth() {
		if (this.user) {
			return this.refreshIdToken(); // Won't do anything if the token is valid.
		} else {
			throw Error('The user must be signed-in to use this method.');
		}
	}

	/**
	 * Updates the user data in localStorage.
	 * @param {Object} userData New user data.
	 * @param {boolean} [updateStorage = true] Check whether to update localStorage or not.
	 * @private
	 */
	async setState(userData, persist = true, emit = true) {
		this.user = userData;
		if (persist) {
			await this.storage[userData ? 'set' : 'remove'](
				this.sKey('User'),
				JSON.stringify(userData)
			);
		}
		if (emit) {
			this.emit();
		}
	}

	/**
	 * Sign out the currently signed-in user.
	 * Removes all data stored in the storage that's associated with the user.
	 */
	signOut() {
		return this.setState(null);
	}

	/**
	 * Refreshes the idToken by using the locally stored refresh token only if the idToken has expired.
	 * @private
	 */
	async refreshIdToken() {
		// If the idToken didn't expire, return.
		if (Date.now() < this.user.tokenManager.expiresAt) {
			return;
		}
		// If the request for a new token was already made, then wait for it and return.
		else if (this._ref) {
			return void (await this._ref);
		}
		// If the idToken is expired or the request for a new token was made, then refresh.
		else {
			try {
				// Save the promise when this function is called,
				// else we don't make more than one request.
				this._ref = this.api('token', {
					grant_type: 'refresh_token',
					refresh_token: this.user.tokenManager.refreshToken,
				}).then(data => {
					const tokenManager = {
						idToken: data.id_token,
						refreshToken: data.refresh_token,
						expiresAt: data.expiresAt,
					};
					return this.setState({ ...this.user, tokenManager }, true, false);
				});
				await this._ref;
			} finally {
				this._ref = null;
			}
		}
	}

	/**
	 * Uses native fetch, but adds authorization headers, otherwise, the API is exactly the same as native fetch.
	 * @param {Request|Object|string} resource A request to send. It can be a resource or an options object.
	 * @param {Object} init An options object.
	 */
	async authorizedRequest(resource, init) {
		const request =
			resource instanceof Request
				? resource
				: new Request(resource, init);

		if (this.user) {
			await this.refreshIdToken(); // Won't do anything if the token didn't expire yet.
			request.headers.set(
				'Authorization',
				`Bearer ${this.user.tokenManager.idToken}`
			);
		}

		return fetch(request);
	}

	/**
	 * Signs in or signs up a user by exchanging a custom authentication token.
	 * @param {string} token The custom token.
	 */
	async signInWithCustomToken(token) {
		// Try to exchange the Auth Code for an idToken and refreshToken.
		// And then get the user profile.
		return await this.fetchProfile(
			await this.api('signInWithCustomToken', {
				token,
				returnSecureToken: true,
			})
		);
	}

	/**
	 * Starts the auth flow of a federated ID provider.
	 * Also, it will redirect the page to the federated sign-in page.
	 * @param {oauthFlowOptions|string} options An options object or a string with the name of the provider.
	 */
	async signInWithProvider(options) {
		if (!this.redirectUri) {
			throw Error(
				'In order to use an Identity provider you should initiate the "Auth" instance with a "redirectUri".'
			);
		}

		// The options can be a string or an object,
		// so here we make sure we extract the correct data in each case.
		const { provider, oauthScope, context, linkAccount } =
			typeof options === 'string'
				? { provider: options }
				: options;

		// Make sure the user is signed-in when an 'account link' was requested.
		if (linkAccount) {
			await this.enforceAuth();
		}

		// Get the URL and other data necessary for authentication.
		const { authUri, sessionId } = await this.api('createAuthUri', {
			continueUri: this.redirectUri,
			authFlowType: 'CODE_FLOW',
			providerId: provider,
			oauthScope,
			context,
		});

		// Save the sessionId that we just received in localStorage.
		// It's required to finish the auth flow because I believe
		// this is used to mitigate CSRF attacks (no docs on this...).
		await this.storage.set(this.sKey('SessionId'), sessionId);

		// Save if this is a fresh sign-in or a 'link account' request.
		if (linkAccount) {
			await this.storage.set(this.sKey('LinkAccount'), true);
		}

		// Finally, redirect the page to the auth endpoint.
		location.assign(authUri);
	}

	/**
	 * Signs in or signs up a user using credentials from an Identity Provider (IdP) after a redirect.
	 * It will fail silently if the URL doesn't have a 'code' search param.
	 * @param {string} [requestUri] The request URI with the authorization code, state, etc. from the IdP.
	 * @private
	 */
	async finishProviderSignIn(requestUri = location.href) {
		// Get the sessionId we received before the redirect from storage.
		const sessionId = await this.storage.get(this.sKey('SessionId'));
		// Get the indication if this was a 'link account' request.
		const linkAccount = await this.storage.get(this.sKey('LinkAccount'));

		// Check for the edge case in which the user signed-out
		// before completing the linkAccount request.
		if (linkAccount && !this.user) {
			throw Error(
				'Request to "Link account" was made, but user is no longer signed-in'
			);
		} else {
			await this.storage.remove(this.sKey('LinkAccount'));

			// Try to exchange the Auth Code for an idToken and refreshToken.
			const { idToken, refreshToken, expiresAt, context } = await this.api(
				'signInWithIdp',
				{
					// If this is a 'link account' flow, then attach the idToken of the currently signed-in account.
					idToken: linkAccount ? this.user.tokenManager.idToken : undefined,
					requestUri,
					sessionId,
					returnSecureToken: true,
				}
			);

			// Now, get the user profile.
			await this.fetchProfile({ idToken, refreshToken, expiresAt });

			// Remove sensitive data from the URLSearch params in the location bar.
			history.replaceState(null, null, location.origin + location.pathname);

			return context;
		}
	}

	/**
	 * Handles all sign-in flows that complete via redirects.
	 * Fails silently if no redirect was detected.
	 */
	async handleSignInRedirect() {
		// OAuth Federated Identity Provider flow.
		if (location.href.match(/[&?]code=/)) {
			return this.finishProviderSignIn();
		}
		// Email sign-in flow.
		else if (location.href.match(/[&?]oobCode=/)) {
			const oobCode = location.href.match(/[?&]oobCode=([^&]+)/)[1];
			const email = location.href.match(/[?&]email=([^&]+)/)[1];
			const expiresAt = Date.now() + 3600 * 1000;
			const { idToken, refreshToken } = await this.api('signInWithEmailLink', {
				oobCode,
				email,
			});
			// Now, get the user profile.
			await this.fetchProfile({ idToken, refreshToken, expiresAt });
			// Remove sensitive data from the URLSearch params in the location bar.
			history.replaceState(null, null, location.origin + location.pathname);
		}
	}

	/**
	 * Signs up with email and password or anonymously when no arguments are passed.
	 * Automatically signs the user in on completion.
	 * @param {string} [email] An email for the user to pass.
	 * @param {string} [password] A password for the user to pass.
	 */
	async signUp(email, password) {
		// Sign up and then retrieve the user profile and persist it in the session.
		return await this.fetchProfile(
			await this.api('signUp', {
				email,
				password,
				returnSecureToken: true,
			})
		);
	}

	/**
	 * Signs in a user with email and password.
	 * @param {string} email
	 * @param {string} password
	 */
	async signIn(email, password) {
		// Sign in and then retrieve the user profile and persist it in the session.
		return await this.fetchProfile(
			await this.api('signInWithPassword', {
				email,
				password,
				returnSecureToken: true,
			})
		);
	}

	/**
	 * Sends an out-of-band confirmation code for an account.
	 * It can be used to reset a password, to verify an email address and send a sign-in email link.
	 * The email argument is not needed if verifying an email (the argument is ignored). Otherwise, it is required.
	 * @param {'PASSWORD_RESET'|'VERIFY_EMAIL'|'EMAIL_SIGNIN'} requestType The type of out-of-band (OOB) code to send.
	 * @param {string} [email] When the `requestType` is `PASSWORD_RESET` or `EMAIL_SIGNIN` you need to provide an email address.
	 * @returns {Promise}
	 */
	async sendOobCode(requestType, email) {
		const verifyEmail = requestType === 'VERIFY_EMAIL';
		if (verifyEmail) {
			await this.enforceAuth();
			email = this.user.email;
		}

		return void this.api('sendOobCode', {
			idToken: verifyEmail ? this.user.tokenManager.idToken : undefined,
			requestType,
			email,
			continueUrl: this.redirectUri + `?email=${email}`,
		});
	}

	/**
	 * Resets the password by using a reset code.
	 * It can also be used to verify oobCode by not passing a password.
	 * @param {string} code
	 * @returns {string} The email of the account to which the code was issued.
	 */
	async resetPassword(oobCode, newPassword) {
		const { email } = await this.api('resetPassword', { oobCode, newPassword });

		return email;
	}

	/**
	 * Returns info about all providers associated with a specified email.
	 * @param {string} email The user's email address.
	 * @returns {ProvidersForEmailResponse}
	 */
	async fetchProvidersForEmail(email) {
		const response = await this.api('createAuthUri', {
			identifier: email,
			continueUri: location.href,
		});
		delete response.kind;
		return response;
	}

	/**
	 * Gets the user data from the server, and updates the local caches.
	 * @param {Object} [tokenManager] Only when not signed-in.
	 * @throws Will throw if the user is not signed-in.
	 */
	async fetchProfile(tokenManager = this.user && this.user.tokenManager) {
		if (!tokenManager) {
			await this.enforceAuth();
		}

		const lookupResponse = await this.api('lookup', {
			idToken: tokenManager.idToken,
		});

		const [userData] = lookupResponse.users;
		userData.tokenManager = tokenManager;
		delete userData.kind;

		await this.setState(userData);
	}

	/**
	 * Updates the user's profile.
	 * @param {Object} newData An object with the new data.
	 * @throws Will throw if the user is not signed-in.
	 */
	async updateProfile(newData) {
		await this.enforceAuth();

		// Calculate the expiration date for the idToken.
		const updatedData = await this.api('update', {
			...newData,
			idToken: this.user.tokenManager.idToken,
			returnSecureToken: true,
		});

		const { idToken, refreshToken, expiresAt } = updatedData;

		if (updatedData.idToken) {
			updatedData.tokenManager = { idToken, refreshToken, expiresAt };
		} else {
			updatedData.tokenManager = this.user.tokenManager;
		}

		delete updatedData.kind;
		delete updatedData.idToken;
		delete updatedData.refreshToken;

		await this.setState(updatedData);
	}

	/**
	 * Deletes the currently signed-in account then sign out.
	 * @throws Will throw if the user is not signed-in.
	 */
	async deleteAccount() {
		await this.enforceAuth();
		await this.api(
			'delete',
			JSON.stringify({ idToken: this.user.tokenManager.idToken })
		);
		this.signOut();
	}
}
