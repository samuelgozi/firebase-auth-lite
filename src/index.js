import errors from './errors';

// Most of the info about the API can be found in the firebase docs
// https://firebase.google.com/docs/reference/rest/auth/

function getHumanReadableError(error) {
	// First check if the user is connected to the internet(this is not always correct).
	if(!navigator.onLine) return 'You are not connected to the Internet.';

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
 * This function checkes that that the response object returns with the 'ok' boolean set to true,
 * thats Fetch API's way of telling us that the response status is in the "successful" range.
 */
function handleRequestErrors(response) {
	if (!response.ok) {
		throw Error(response.statusText);
	}
	return response;
}


/*
 * The public API
 */
export default class {
	constructor({apiKey, projectId}) {
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
			}).then(handleRequestErrors).then(response => response.json());

			// Calculate and add the expiration time of the token
			authData.expirationTime = Number(authData.expiresIn) + requestTime * 1000;
			// Save the session on localStorage
			localStorage.setItem(this._sessionKey, JSON.stringify(authData));
		} catch (error) {
			throw Error(getHumanReadableError(error));
		}
	}

	/*
	 * Remove the session data from the local storage.
	 */
	signOut() {
		localStorage.removeItem(this._sessionKey);
	}

	/*
	 * Getter for the user info.
	 * Removes unnecessary info from the user object
	 * Returns undefined when no user is signed in.
	 */
	get user() {
		let userData = localStorage.getItem(this._sessionKey);
		if(!userData) return undefined;

		// If there is a user, then parse it, since its saved as JSON.
		userData = JSON.parse(userData);
		let {displayName, email, localId, registered} = userData;
		return {displayName, email, localId, registered};
	}
}
