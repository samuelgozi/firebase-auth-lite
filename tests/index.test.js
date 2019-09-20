import AuthAPI from '../src/index.js';
import config from '../config.js';
import fetch from 'node-fetch';

window.fetch = fetch;

/*
 * In order to test this package you need to create a config.js file in the root folder
 * that exports a firebase web configuration object with the apiKey and projectId.
 * export default {
 *	apiKey: '[API KEY]',
 *	projectId: '[PROJECT ID]',
 *	};
 *
 * Also you need to have a username with the email: test@test.com
 * And a password: 123456
 *
 * This will be required until i have time to mock the API.
 */
const auth = new AuthAPI(config);

test("Throws error is used doesn't exist", () => {
	expect.assertions(4);

	return auth.signIn('test@test.com', '123456').then(() => {
		const session = JSON.parse(localStorage.getItem(auth._sessionKey));

		expect(session).toBeDefined();
		expect(session).toHaveProperty('email', 'test@test.com');
		expect(session).toHaveProperty('kind', 'identitytoolkit#VerifyPasswordResponse');
		expect(session).toHaveProperty('registered', true);
	});
});

test('Saves session into the LocalStorage after logging-in', () => {
	expect.assertions(4);

	return auth.signIn('test@test.com', '123456').then(() => {
		const session = JSON.parse(localStorage.getItem(auth._sessionKey));

		expect(session).toBeDefined();
		expect(session).toHaveProperty('email', 'test@test.com');
		expect(session).toHaveProperty('kind', 'identitytoolkit#VerifyPasswordResponse');
		expect(session).toHaveProperty('registered', true);
	});
});

test("Retrieves the current user's info when logged in", () => {
	const user = auth.user;

	expect(user).toHaveProperty('displayName');
	expect(user).toHaveProperty('email');
	expect(user).toHaveProperty('localId');
	expect(user).toHaveProperty('registered');
});

test('Removes session from the local storage after logging-out', () => {
	auth.signOut();

	expect(localStorage.getItem(auth._sessionKey)).toBeNull();
});

test("Returns 'undefined' when the user isn't logged in", () => {
	const user = auth.user;

	expect(user).toBeUndefined();
});
