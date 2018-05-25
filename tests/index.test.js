import AuthAPI from '../src/index.js';
import config from '../config';
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
 * This will be required untill i have time to mock the API.
 */
const auth = new AuthAPI(config);

test('Saves session into the LocalStorage after logging-in', () => {
	expect.assertions(4);

	return auth.signIn('test@test.com', '123456').then(() => {
		const cookie = JSON.parse(localStorage.getItem(auth._sessionKey));

		expect(cookie).toBeDefined();
		expect(cookie).toHaveProperty('email', 'test@test.com');
		expect(cookie).toHaveProperty('kind', 'identitytoolkit#VerifyPasswordResponse');
		expect(cookie).toHaveProperty('registered', true);
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
