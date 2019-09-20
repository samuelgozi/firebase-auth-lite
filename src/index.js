import errors from './errors';

/*
 * Most of the info about the API can be found in the firebase docs
 * https://firebase.google.com/docs/reference/rest/auth/
 */

/**
 * Returns a human readable error for a error code.
 * @prop {string} error the error code from the rest API
 * @returns {string} human readable error.
 */
function getHumanReadableError(error) {
	// First check if the user is connected to the internet(this is not always correct).
	if (!navigator.onLine) return 'You are not connected to the Internet.';

	// Try to get the correct message(sometimes in different places).
	let errorMessage = error.error ? error.error.message : error.message;

	/*
	 * Check if we have a more readable error for this error code in our language files.
	 * If we do have one, return it, else return what we have.
	 */
	return errors[errorMessage] || errorMessage;
}

/*
 * The Fetch API throws only when there is a network connection issue, therefore
 * we need to manually check for the response status and throw an error ourselves.
 *
 * This function checks that that the response object returns with the 'ok' boolean set to true,
 * thats Fetch API's way of telling us that the response status is in the "successful" range.
 */
function handleRequestErrors(response) {
	if (!response.ok) {
		throw Error(response.statusText);
	}
	return response;
}

/**
 * Authentication class.
 * Encapsulates logic for authentication and session
 * management.
 *
 * @param {Object} config Firebase config object
 * @param {string} config.apiKey The aPI key fot this firebase project
 * @param {string} config.projectId   The project ID for this firebase project.
 */
export default class Auth {
	constructor({ apiKey, projectId }) {
		this._endpoints = {
			signUp: 'https://www.googleapis.com/identitytoolkit/v3/relyingparty/signupNewUser?key=' + apiKey,
			signIn: 'https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword?key=' + apiKey,
			token: 'https://securetoken.googleapis.com/v1/token?key=' + apiKey,
			updateProfile: 'https://www.googleapis.com/identitytoolkit/v3/relyingparty/setAccountInfo?key=' + apiKey
		};
		this._sessionKey = projectId + ':' + apiKey;
	}

	/*
	 * Request a session ID from the REST API, then save it in local storage.
	 */
	async signIn(email, password) {
		try {
			let requestTime = Date.now(); // Used to calculate the expiration time of the token.
			let authData = await fetch(this._endpoints.signIn, {
				method: 'POST',
				body: JSON.stringify({ email, password, returnSecureToken: true }),
				headers: { 'Content-Type': 'application/json' }
			})
				.then(handleRequestErrors)
				.then(response => response.json());

			console.log(authData);

			// Calculate and add the expiration time of the token
			authData.expirationDate = new Date(Number(authData.expiresIn) + requestTime * 1000);

			// Save the session
			this.saveSession(authData);
		} catch (error) {
			throw Error(getHumanReadableError(error));
		}
	}

	/*
	 * Exchange a refresh token for an ID token.
	 * returns a promise.
	 */
	async refreshIdToken() {
		const session = this.session;
		if (session === undefined) throw Error("Can't refresh the ID token because no session has been found");

		try {
			let requestTime = Date.now(); // Used to calculate the expiration time of the token.
			let refreshTokenData = await fetch(this._endpoints.token, {
				method: 'POST',
				body: JSON.stringify({
					gran_token: 'refresh_token',
					refresh_token: session.refreshToken
				}),
				headers: { 'Content-Type': 'application/json' }
			})
				.then(handleRequestErrors)
				.then(response => response.json());

			// Calculate and add the expiration time of the token
			refreshTokenData.expirationDate = new Date(Number(refreshTokenData.expires_in) + requestTime * 1000);

			// Update the session.
			this.updateSession(refreshTokenData);
		} catch (error) {
			throw Error(getHumanReadableError(error));
		}
	}

	/*
	 * Save the session to local storage and as property of this class for faster access.
	 */
	saveSession(session) {
		// Check that the session has an "expiration time".
		if (Object.prototype.toString.call(session.expirationDate) !== '[object Date]')
			throw Error('The session should have a valid expiration date');

		// Save the session on memory(in this instance of the class)
		this._session = session;

		// Save the session on the local storage.
		localStorage.setItem(this._sessionKey, JSON.stringify(session));
	}

	/*
	 * Update the old session's ID and refresh tokens.
	 */
	updateSession(refreshTokenResponse) {
		// Extract the data
		let { expires_in: expiresIn, refresh_token: refreshToken, id_token: idToken } = refreshTokenResponse;

		// Create a new object with the updated data.
		const updatedSession = Object.assign(this.session, {
			expiresIn,
			refreshToken,
			idToken
		});

		// Save the new session object.
		this.saveSession(updatedSession);
	}

	/*
	 * Remove the session data from the local storage.
	 */
	signOut() {
		// Remove the session from memory.
		this._session = undefined;

		// Remove it from memory.
		localStorage.removeItem(this._sessionKey);
	}

	/*
	 * Return the user session from the local storage or from memory.
	 */
	get session() {
		// Try to get the session from memory, and if not set then try the local storage.
		const session = this._session || JSON.parse(localStorage.getItem(this._sessionKey));

		// If no session found, return undefined.
		if (!session) return undefined;

		// If a session was found, return it.
		return session;
	}

	/*
	 * Getter for the user info.
	 * Removes unnecessary info from the user object
	 * Returns undefined when no user is signed in.
	 */
	get user() {
		const session = this.session;
		// if there is no session then return undefined.
		if (this.session === undefined) return undefined;

		// If there is a session then create a new object with only the relevant info.
		let { displayName, email, localId, registered } = session;
		return { displayName, email, localId, registered };
	}
}
