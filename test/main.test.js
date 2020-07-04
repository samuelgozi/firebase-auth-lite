import Auth from '../src/main.js';

let assignMock = jest.fn(href => {
	window.location.href = href;
});

delete window.location;
window.location = { assign: assignMock, href: 'currentUri' };

const mockUserData = {
	email: 'test@example.com',
	tokenManager: {
		idToken: 'idTokenString',
		expiresAt: Date.now() + 3600 * 1000 // In one hour from now.
	}
};

async function mockLoggedIn(auth) {
	// Await initialization.
	await new Promise(resolve => {
		auth.listen(resolve);
	});

	auth.user = mockUserData;
}

beforeEach(() => {
	fetch.resetMocks();
	assignMock.mockClear();
	window.location.href = 'currentUri';
	localStorage.removeItem('Auth:User:key:default');
	localStorage.removeItem('Auth:LinkAccount:key:default');
});

describe('localStorageAdapter()', () => {
	const auth = new Auth({ apiKey: 'key' });

	test('Implements the right methods', () => {
		const keys = ['set', 'get', 'remove'];
		expect(Object.keys(auth.storage)).toEqual(keys);

		keys.forEach(key => {
			expect(typeof auth.storage[key]).toEqual('function');
		});
	});

	test('set() adds an item to local storage', async () => {
		await auth.storage.set('testKey', 'testValue');

		expect(localStorage.getItem('testKey')).toEqual('testValue');
	});

	test('get() returns an item from local storage', async () => {
		expect(await auth.storage.get('testKey')).toEqual('testValue');
	});
});

describe('Auth', () => {
	describe('constructor', () => {
		test('Throws when the "apiKey" argument is missing', () => {
			expect(() => {
				new Auth();
			}).toThrow('The argument "apiKey" is required');

			expect(() => {
				new Auth({});
			}).toThrow('The argument "apiKey" is required');
		});

		describe('Initializes the "user" property', () => {
			test('Reads the username from storage when already signed-in', async () => {
				// The constructor makes some requests.
				// We have to mock them for this not to throw
				fetch.mockResponse(`{ "users": [${JSON.stringify(mockUserData)}] }`);

				localStorage.setItem('Auth:User:key:default', JSON.stringify(mockUserData));
				const auth = new Auth({ apiKey: 'key' });

				const userData = await new Promise(resolve => {
					auth.listen(resolve);
				});

				expect(userData).toEqual(mockUserData);
				expect(auth.user).toEqual(mockUserData);
			});

			test('Updates the stored data if the user is signed-in', async () => {
				// The constructor makes some requests.
				// We have to mock them for this not to throw
				fetch.mockResponse('{"users": [{ "username": "updated!" }]}');

				localStorage.setItem('Auth:User:key:default', JSON.stringify(mockUserData));
				const auth = new Auth({ apiKey: 'key' });

				// Await for the second update to happen.
				// The first one is for data from local storage.
				await new Promise(resolve => {
					auth.listen(resolve);
				});
				const userData = await new Promise(resolve => {
					auth.listen(resolve);
				});

				expect(auth.user.username).toEqual('updated!');
				expect(userData).toEqual(auth.user);
			});

			test('Refreshed the token when signed-in and token has expired', async () => {
				fetch.mockResponses('{ "id_token": "123", "refresh_token": "456" }', '{"users": [{ "updated": true }]}');

				localStorage.setItem(
					'Auth:User:key:default',
					JSON.stringify({
						email: 'test@example.com',
						tokenManager: {
							idToken: 'idTokenString',
							expiresAt: Date.now() - 3600 * 1000 // One hour ago.
						}
					})
				);

				const auth = new Auth({ apiKey: 'key' });

				// Await for the second update to happen.
				// The first one is from local storage.
				await new Promise(resolve => {
					auth.listen(resolve);
				});

				await new Promise(resolve => {
					auth.listen(resolve);
				});

				expect(fetch.mock.calls[0][0]).toEqual('https://securetoken.googleapis.com/v1/token?key=key');
				expect(fetch.mock.calls[1][0]).toEqual('https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=key');
				expect(fetch.mock.calls.length).toEqual(2);
				expect(auth.user.tokenManager.idToken).toEqual('123');
				expect(auth.user.tokenManager.refreshToken).toEqual('456');
			});
		});

		test('Calls the listeners when the user is not signed-in', async () => {
			const auth = new Auth({ apiKey: 'key' });

			const userData = await new Promise(resolve => {
				auth.listen(resolve);
			});

			expect(userData).toEqual(null);
			expect(auth.user).toEqual(null);
		});

		test("Doesn't make any requests when the user is not signed-in", async () => {
			// The constructor makes some requests.
			// We have to mock them for this not to throw
			fetch.mockResponse('{}');

			await new Promise(resolve => {
				new Auth({ apiKey: 'key' });

				// Wait for requests to be made.
				// We need this because the constructor can't be async.
				setTimeout(resolve, 1000);
			});

			expect(fetch.mock.calls.length).toEqual(0);
		});

		test('Signs out a previously signed in user when their token has expired', async () => {
			fetch.mockResponse('{"error": {"message": "TOKEN_EXPIRED"}}', { status: 403 });

			// Previously signed in user
			localStorage.setItem(
				'Auth:User:key:default',
				JSON.stringify({
					email: 'test@example.com',
					tokenManager: {
						idToken: 'idTokenString',
						expiresAt: Date.now()
					}
				})
			);

			const auth = new Auth({ apiKey: 'key' });

			// First call to the listener will be done after reading the local storage.
			// After that a request to update the user data will be made, and it will return
			// the fetch error "TOKEN_EXPIRED", the constructor will catch that, then
			// sign out the user and call the listener a second time.
			let calls = 0;
			const userData = await new Promise(resolve => {
				auth.listen(user => {
					calls++;
					if (calls === 2) resolve(user);
				});
			});

			expect(fetch.mock.calls.length).toEqual(1);
			expect(userData).toBe(null);
		});

		test('Signs out a previously signed in user when their token is invalid', async () => {
			fetch.mockResponse('{"error": {"message": "INVALID_ID_TOKEN"}}', { status: 403 });

			// Previously signed in user
			localStorage.setItem(
				'Auth:User:key:default',
				JSON.stringify({
					email: 'test@example.com',
					tokenManager: {
						idToken: 'idTokenString',
						expiresAt: Date.now()
					}
				})
			);

			const auth = new Auth({ apiKey: 'key' });

			// First call to the listener will be done after reading the local storage.
			// After that a request to update the user data will be made, and it will return
			// the fetch error "INVALID_ID_TOKEN", the constructor will catch that, then
			// sign out the user and call the listener a second time.
			let calls = 0;
			const userData = await new Promise(resolve => {
				auth.listen(user => {
					calls++;
					if (calls === 2) resolve(user);
				});
			});

			expect(fetch.mock.calls.length).toEqual(1);
			expect(userData).toBe(null);
		});

		describe('Storage events listener', () => {
			test('updates the instance user data', () => {
				const auth = new Auth({ apiKey: 'key' });
				const mockEvent = new Event('storage');

				mockEvent.key = auth.sKey('User');
				mockEvent.newValue = '{"hello":"world!"}';

				window.dispatchEvent(mockEvent);

				expect(auth.user).toEqual({ hello: 'world!' });
			});

			test('Triggers change event', () => {
				const auth = new Auth({ apiKey: 'key' });
				const mockEvent = new Event('storage');
				const listener = jest.fn(() => {});

				auth.listen(listener);

				mockEvent.key = auth.sKey('User');
				mockEvent.newValue = '{"hello":"world!"}';

				window.dispatchEvent(mockEvent);

				expect(listener).toHaveBeenCalledTimes(1);
				expect(listener).toHaveBeenCalledWith({ hello: 'world!' });
			});

			test('Nothing happens when an unrelated storage event is triggered', () => {
				const auth = new Auth({ apiKey: 'key' });
				const mockEvent = new Event('storage');
				const listener = jest.fn(() => {});

				auth.listen(listener);

				mockEvent.key = 'somethingElse';
				mockEvent.newValue = '{"hello":"world!"}';

				window.dispatchEvent(mockEvent);

				expect(listener).toHaveBeenCalledTimes(0);
				expect(auth.user).toEqual(undefined);
			});
		});
	});

	describe('listen() & emit()', () => {
		test('All listeners are called', () => {
			const auth = new Auth({ apiKey: 'key' });

			const listener1 = jest.fn(() => {});
			const listener2 = jest.fn(() => {});
			const listener3 = jest.fn(() => {});

			auth.listen(listener1);
			auth.listen(listener2);
			auth.listen(listener3);
			auth.emit();

			expect(listener1).toHaveBeenCalledTimes(1);
			expect(listener2).toHaveBeenCalledTimes(1);
			expect(listener3).toHaveBeenCalledTimes(1);

			expect(listener1).toHaveBeenCalledWith(auth.user);
			expect(listener2).toHaveBeenCalledWith(auth.user);
			expect(listener3).toHaveBeenCalledWith(auth.user);
		});

		test('listen() returns a function to remove the listener', () => {
			const auth = new Auth({ apiKey: 'key' });

			const listener1 = jest.fn(() => {});
			const listener2 = jest.fn(() => {});
			const listener3 = jest.fn(() => {});

			const unlisten = auth.listen(listener1);
			auth.listen(listener2);
			auth.listen(listener3);

			unlisten();
			auth.emit();

			expect(listener1).toHaveBeenCalledTimes(0);
			expect(listener2).toHaveBeenCalledTimes(1);
			expect(listener3).toHaveBeenCalledTimes(1);
		});
	});

	describe('sKey', () => {
		test('returns correct key', () => {
			const auth = new Auth({ apiKey: 'key' });

			expect(auth.sKey('User')).toEqual('Auth:User:key:default');
			expect(auth.sKey('LinkAccount')).toEqual('Auth:LinkAccount:key:default');
			expect(auth.sKey('SessionId')).toEqual('Auth:SessionId:key:default');
			expect(auth.sKey('Whatever...')).toEqual('Auth:Whatever...:key:default');
		});
	});

	describe('api()', () => {
		test('errors are parsed correctly', async () => {
			fetch.mockResponses(
				[
					JSON.stringify({
						error: {
							code: 400,
							message: 'OPERATION_NOT_ALLOWED : The identity provider configuration is disabled.'
						}
					}),
					{ status: 400 }
				],

				[
					JSON.stringify({
						error: {
							code: 400,
							message: 'EMAIL_NOT_FOUND'
						}
					}),
					{ status: 400 }
				],

				[
					JSON.stringify({
						error: {
							code: 400,
							message: "Invalid value at 'id_token' (TYPE_STRING), false"
						}
					}),
					{ status: 400 }
				]
			);

			const auth = new Auth({ apiKey: 'key' });

			await expect(auth.api('test', 'body')).rejects.toThrow('OPERATION_NOT_ALLOWED');
			await expect(auth.api('test', 'body')).rejects.toThrow('EMAIL_NOT_FOUND');
			await expect(auth.api('test', 'body')).rejects.toThrow("Invalid value at 'id_token' (TYPE_STRING), false");
		});
	});

	describe('enforceAuth()', () => {
		test('Throws when the user is not signed-in', async () => {
			const auth = new Auth({ apiKey: 'key' });
			await expect(auth.enforceAuth()).rejects.toThrow('The user must be signed-in to use this method.');
		});

		test("Doesn't make any requests when the user is not signed-in", async () => {
			// The constructor makes some requests.
			// We must mock them, to prevent a throw
			fetch.mockResponse('{}');

			try {
				const auth = new Auth({ apiKey: 'key' });
				await auth.enforceAuth();
			} catch {}

			expect(fetch.mock.calls.length).toEqual(0);
		});
	});

	describe('setState()', () => {
		test('Stores the user data locally', async () => {
			const auth = new Auth({ apiKey: 'key' });
			await auth.setState({ test: 'working' });

			expect(await auth.storage.get('Auth:User:key:default')).toEqual(JSON.stringify({ test: 'working' }));
		});

		test("Doens't update storage when second argument is false", async () => {
			const auth = new Auth({ apiKey: 'key' });
			await auth.setState({ test: 'working' }, false);

			expect(await auth.storage.get('Auth:User:key:default')).toEqual(null);
		});

		test('Updates the "user" property with the new data', async () => {
			const auth = new Auth({ apiKey: 'key' });

			// Wait instantiation to finish.
			await new Promise(resolve => auth.listen(resolve));
			await auth.setState({ test: 'working' });

			expect(auth.user).toEqual({ test: 'working' });
		});

		test('Fires an event', async () => {
			const auth = new Auth({ apiKey: 'key' });

			const callback = jest.fn(() => {});
			auth.listen(callback);

			await auth.setState();

			// One time in instantiation, and one
			// time for the called method.
			expect(callback).toHaveBeenCalledTimes(2);
		});
	});

	describe('signOut()', () => {
		test('Deletes user data from storage', async () => {
			const auth = new Auth({ apiKey: 'key' });

			await mockLoggedIn(auth);
			await auth.signOut();

			expect(localStorage.getItem('Auth:User:key:default')).toEqual(null);
		});

		test('Updates the "user" property', async () => {
			const auth = new Auth({ apiKey: 'key' });

			auth.user = {};

			await auth.signOut();

			expect(auth.user).toEqual(null);
		});

		test('Fires an event', async () => {
			const auth = new Auth({ apiKey: 'key' });

			const callback = jest.fn(() => {});
			auth.listen(callback);

			await auth.signOut();

			// One time in instantiation, and one
			// time for the called method.
			expect(callback).toHaveBeenCalledTimes(2);
		});
	});

	describe('refreshIdToken()', () => {
		test('Returns if token is still valid', async () => {
			const auth = new Auth({ apiKey: 'key' });
			await mockLoggedIn(auth);
			await auth.refreshIdToken();

			expect(fetch.mock.calls.length).toEqual(0);
		});

		test('Allow only one concurrent fetch request', async () => {
			// The constructor makes some requests.
			// We have to mock them for this not to throw
			fetch.mockResponse('{"users": [{ "updated": true }]}');

			const auth = new Auth({ apiKey: 'key' });
			// Mock signed-in user.
			auth.user = {
				tokenManager: {
					idToken: 'idTokenString',
					// Mock old expiration time
					expiresAt: Date.now() - 3600 * 1000
				}
			};

			auth.refreshIdToken();
			auth.refreshIdToken();
			auth.refreshIdToken();
			await auth.refreshIdToken();

			expect(fetch.mock.calls.length).toEqual(1);
		});

		test('Sets correct expiration time', async () => {
			const responseDate = 'Fri, 10 Apr 2020 11:08:13 GMT';

			fetch.mockResponse('{"users": [{ "updated": true }]}', {
				headers: {
					date: responseDate
				}
			});

			const auth = new Auth({ apiKey: 'key' });
			// Mock signed-in user.
			auth.user = {
				tokenManager: {
					idToken: 'idTokenString',
					// Mock old expiration time
					expiresAt: Date.now() - 1000
				}
			};

			const expectedExpiration = Date.parse(responseDate) + 3600 * 1000;
			await auth.refreshIdToken();

			// Check that the time is close enough by allowing
			// a few milliseconds of delay, since the function takes time to run.
			expect(auth.user.tokenManager.expiresAt).toEqual(expectedExpiration);
			expect(typeof auth.user.tokenManager.expiresAt).toEqual('number');
		});

		test('Updates id and refresh tokens', async () => {
			// The constructor makes some requests.
			// We have to mock them for this not to throw
			fetch.mockResponse('{"refresh_token": "updated", "id_token": "updated"}');

			const auth = new Auth({ apiKey: 'key' });

			// Mock signed-in user.
			auth.user = {
				tokenManager: {
					idToken: 'idTokenString',
					// Mock old expiration time
					expiresAt: Date.now() - 1000
				}
			};

			await auth.refreshIdToken();

			// Check that the time is close enough by allowing
			// a few milliseconds of delay, since the function takes time to run.
			expect(auth.user.tokenManager.refreshToken).toEqual('updated');
			expect(auth.user.tokenManager.idToken).toEqual('updated');
		});

		test("Doesn't emit", async () => {
			// The constructor makes some requests.
			// We have to mock them for this not to throw
			fetch.mockResponse('{"refresh_token": "updated", "id_token": "updated"}');

			const auth = new Auth({ apiKey: 'key' });
			await mockLoggedIn(auth);

			// Mock signed-in user.
			auth.user = {
				tokenManager: {
					idToken: 'idTokenString',
					// Mock old expiration time
					expiresAt: Date.now() - 1000
				}
			};

			const listener = jest.fn(() => {});
			auth.listen(listener);
			await auth.refreshIdToken();

			expect(listener).toHaveBeenCalledTimes(0);
		});
	});

	describe('AuthorizedRequest()', () => {
		test('Adds Authorization headers when the user is signed-in.', async () => {
			// The constructor makes some requests.
			// We have to mock them for this not to throw
			fetch.mockResponse('{}');

			const auth = new Auth({ apiKey: 'key' });

			await mockLoggedIn(auth);

			await auth.authorizedRequest('http://google.com');

			const headers = fetch.mock.calls[0][0].headers;

			expect(headers.get('Authorization')).toEqual('Bearer idTokenString');
		});

		test("Doesn't change the request when the user is not signed-in", async () => {
			// The constructor makes some requests.
			// We have to mock them for this not to throw
			fetch.mockResponse('{}');

			const auth = new Auth({ apiKey: 'key' });

			const request = new Request('http://google.com');
			await auth.authorizedRequest(request);

			expect(fetch.mock.calls[0][0]).toBe(request);
		});
	});

	describe('signInWithCustomToken()', () => {
		test('Makes the right request', async () => {
			const auth = new Auth({ apiKey: 'key' });

			fetch.mockResponses('{ "idToken": "123", "refreshToken": "456" }', '{"users": [{ "updated": true }]}');

			await auth.signInWithCustomToken('token123');
			const requestBody = JSON.parse(fetch.mock.calls[0][1].body);

			expect(requestBody).toEqual({
				token: 'token123',
				returnSecureToken: true
			});
		});

		test('Updates the userData', async () => {
			const auth = new Auth({ apiKey: 'key' });

			fetch.mockResponses('{ "idToken": "123", "refreshToken": "456" }', '{"users": [{ "updated": true }]}');
			await auth.signInWithCustomToken('token123');

			expect(auth.user.updated).toEqual(true);
		});
	});

	describe('signInWithProvider()', () => {
		test("Throws if a redirect URI wasn't provided on instantiation", async () => {
			const auth = new Auth({ apiKey: 'key' });

			await expect(auth.signInWithProvider()).rejects.toThrow(
				'In order to use an Identity provider, you should initiate the "Auth" instance with a "redirectUri".'
			);
		});

		test('Enforces signed-in user when performing a "linkAccount"', async () => {
			const auth = new Auth({ apiKey: 'key', redirectUri: 'redirectHere' });

			await expect(auth.signInWithProvider({ provider: 'google.com', linkAccount: true })).rejects.toThrow(
				'The user must be signed-in to use this method.'
			);
		});

		test('Makes correct requests', async () => {
			const auth = new Auth({ apiKey: 'key', redirectUri: 'redirectHere', providers: ['google.com'] });

			fetch.mockResponse(
				`{
					"kind": "identitytoolkit#CreateAuthUriResponse",
					"authUri": "https://accounts.google.com/o/oauth2/auth?response_type=code&client_id=831650550875-vuv36e1i0shmu456i1l08rg3vgjhnlhg.apps.googleusercontent.com&redirect_uri=redirectUri&state=state&scope=openid+https://www.googleapis.com/auth/userinfo.email",
					"providerId": "google.com",
					"sessionId": "LwtaMnW9snPfIfm9R1rPTosVpY4"
				}`
			);

			await auth.signInWithProvider('google.com');
			const body = fetch.mock.calls[0][1].body;

			expect(body).toEqual(
				JSON.stringify({
					continueUri: 'redirectHere',
					authFlowType: 'CODE_FLOW',
					providerId: 'google.com'
				})
			);
		});

		test('Saves the correct data to storage', async () => {
			const auth = new Auth({ apiKey: 'key', redirectUri: 'redirectHere', providers: ['google.com'] });

			fetch.mockResponse(
				`{
					"kind": "identitytoolkit#CreateAuthUriResponse",
					"authUri": "https://accounts.google.com/o/oauth2/auth?response_type=code&client_id=831650550875-vuv36e1i0shmu456i1l08rg3vgjhnlhg.apps.googleusercontent.com&redirect_uri=redirectUri&state=state&scope=openid+https://www.googleapis.com/auth/userinfo.email",
					"providerId": "google.com",
					"sessionId": "LwtaMnW9snPfIfm9R1rPTosVpY4"
				}`
			);

			await auth.signInWithProvider('google.com');

			expect(await auth.storage.get('Auth:SessionId:key:default')).toEqual('LwtaMnW9snPfIfm9R1rPTosVpY4');
			expect(await auth.storage.get('Auth:LinkAccount:key:default')).toEqual(null);
		});

		test('Redirects to the received authUri', async () => {
			const auth = new Auth({ apiKey: 'key', redirectUri: 'redirectHere', providers: ['google.com'] });

			fetch.mockResponse(
				`{
					"kind": "identitytoolkit#CreateAuthUriResponse",
					"authUri": "https://accounts.google.com/o/oauth2/auth?response_type=code&client_id=831650550875-vuv36e1i0shmu456i1l08rg3vgjhnlhg.apps.googleusercontent.com&redirect_uri=redirectUri&state=state&scope=openid+https://www.googleapis.com/auth/userinfo.email",
					"providerId": "google.com",
					"sessionId": "LwtaMnW9snPfIfm9R1rPTosVpY4"
				}`
			);

			await auth.signInWithProvider('google.com');

			expect(window.location.href).toEqual(
				'https://accounts.google.com/o/oauth2/auth?response_type=code&client_id=831650550875-vuv36e1i0shmu456i1l08rg3vgjhnlhg.apps.googleusercontent.com&redirect_uri=redirectUri&state=state&scope=openid+https://www.googleapis.com/auth/userinfo.email'
			);
		});
	});

	describe('signUp()', () => {
		test('Makes the right request', async () => {
			const auth = new Auth({ apiKey: 'key' });

			fetch.mockResponses('{ "idToken": "123", "refreshToken": "456" }', '{"users": [{ "updated": true }]}');

			await auth.signUp('email', 'password');
			const requestBody = JSON.parse(fetch.mock.calls[0][1].body);

			expect(requestBody).toEqual({
				email: 'email',
				password: 'password',
				returnSecureToken: true
			});
		});

		test('Updates the userData', async () => {
			const auth = new Auth({ apiKey: 'key' });

			fetch.mockResponses('{ "idToken": "123", "refreshToken": "456" }', '{"users": [{ "updated": true }]}');
			await auth.signUp('email', 'password');

			expect(auth.user.updated).toEqual(true);
		});
	});

	describe('signIn()', () => {
		test('Makes the right request', async () => {
			const auth = new Auth({ apiKey: 'key' });

			fetch.mockResponses('{ "idToken": "123", "refreshToken": "456" }', '{"users": [{ "updated": true }]}');

			await auth.signIn('email', 'password');
			const requestBody = JSON.parse(fetch.mock.calls[0][1].body);

			expect(requestBody).toEqual({
				email: 'email',
				password: 'password',
				returnSecureToken: true
			});
		});

		test('Updates the userData', async () => {
			const auth = new Auth({ apiKey: 'key' });

			fetch.mockResponses('{ "idToken": "123", "refreshToken": "456" }', '{"users": [{ "updated": true }]}');
			await auth.signIn('email', 'password');

			expect(auth.user.updated).toEqual(true);
		});
	});

	describe('senbOobCode()', () => {
		test('Throws when request type is "verify email" but not signed-in', async () => {
			const auth = new Auth({ apiKey: 'key' });
			await expect(auth.sendOobCode('VERIFY_EMAIL')).rejects.toThrow();
		});

		test('Sends correct request to "verify email"', async () => {
			const auth = new Auth({ apiKey: 'key' });

			fetch.mockResponse('{}');
			await mockLoggedIn(auth);
			await auth.sendOobCode('VERIFY_EMAIL');

			expect(fetch.mock.calls[0][1].body).toEqual(
				JSON.stringify({
					idToken: 'idTokenString',
					requestType: 'VERIFY_EMAIL',
					email: 'test@example.com',
					continueUrl: auth.redirectUri + '?email=test@example.com'
				})
			);
		});

		test('Ignores the email field when making "verify email" request', async () => {
			const auth = new Auth({ apiKey: 'key' });

			fetch.mockResponse('{}');

			await mockLoggedIn(auth);
			await auth.sendOobCode('VERIFY_EMAIL', 'myemail@email.com');

			expect(fetch.mock.calls[0][1].body).toEqual(
				JSON.stringify({
					idToken: 'idTokenString',
					requestType: 'VERIFY_EMAIL',
					email: 'test@example.com',
					continueUrl: auth.redirectUri + '?email=test@example.com'
				})
			);
		});

		test('Sends correct request to the other options', async () => {
			const auth = new Auth({ apiKey: 'key' });
			auth.user = mockUserData;

			fetch.mockResponses('{}', '{}');
			await auth.sendOobCode('PASSWORD_RESET', 'myemail@email.com');
			await auth.sendOobCode('EMAIL_SIGNIN', 'myemail@email.com');

			expect(fetch.mock.calls[0][1].body).toEqual(
				JSON.stringify({
					requestType: 'PASSWORD_RESET',
					email: 'myemail@email.com',
					continueUrl: auth.redirectUri + '?email=myemail@email.com'
				})
			);

			expect(fetch.mock.calls[1][1].body).toEqual(
				JSON.stringify({
					requestType: 'EMAIL_SIGNIN',
					email: 'myemail@email.com',
					continueUrl: auth.redirectUri + '?email=myemail@email.com'
				})
			);
		});
	});

	describe('resetPassword()', () => {
		test('Sends the correct request', async () => {
			const auth = new Auth({ apiKey: 'key' });
			fetch.mockResponse('{}');

			await mockLoggedIn(auth);
			await auth.resetPassword('code', 'password');

			expect(fetch.mock.calls[0][1].body).toEqual(
				JSON.stringify({
					oobCode: 'code',
					newPassword: 'password'
				})
			);
		});

		test('Only sends oobCode when password is missing', async () => {
			const auth = new Auth({ apiKey: 'key' });
			fetch.mockResponse('{}');

			await mockLoggedIn(auth);
			await auth.resetPassword('code');

			expect(fetch.mock.calls[0][1].body).toEqual('{"oobCode":"code"}');
		});

		test('Returns the email of the account', async () => {
			const auth = new Auth({ apiKey: 'key' });
			fetch.mockResponse('{ "email": "test@mail.com" }');

			await mockLoggedIn(auth);
			const response = await auth.resetPassword('code', 'password');

			expect(response).toEqual('test@mail.com');
		});
	});

	describe('fetchProvidersForEmail()', () => {
		test('Sends correct request', async () => {
			const auth = new Auth({ apiKey: 'key' });

			fetch.mockResponse('{}');

			await auth.fetchProvidersForEmail('test@email.com');

			expect(fetch.mock.calls[0][1].body).toEqual(`{"identifier":"test@email.com","continueUri":"${location.href}"}`);
		});

		test('Returns the response without the kind prop', async () => {
			const auth = new Auth({ apiKey: 'key' });

			fetch.mockResponse(`{
				"kind": "identitytoolkit#CreateAuthUriResponse",
				"allProviders": [
					"google.com",
					"password"
				],
				"registered": true,
				"sessionId": "8bbWb2tzjwN-OglfImGs9BXzBJ8",
				"signinMethods": [
					"google.com",
					"password"
				]
			}`);

			const expected = {
				allProviders: ['google.com', 'password'],
				registered: true,
				sessionId: '8bbWb2tzjwN-OglfImGs9BXzBJ8',
				signinMethods: ['google.com', 'password']
			};

			const response = await auth.fetchProvidersForEmail('test@email.com');

			expect(response).toEqual(expected);
		});
	});

	describe('fetchProfile()', () => {
		test('Throws when the user is not signed-in', async () => {
			const auth = new Auth({ apiKey: 'key' });
			await expect(auth.fetchProfile()).rejects.toThrow('The user must be signed-in to use this method.');
		});

		test('Makes correct request', async () => {
			const auth = new Auth({ apiKey: 'key' });
			fetch.mockResponse(`{ "users": [${JSON.stringify(mockUserData)}] }`);

			await mockLoggedIn(auth);
			await auth.fetchProfile();

			expect(fetch.mock.calls[0][1].body).toEqual('{"idToken":"idTokenString"}');
		});

		test('Persists the user data to storage', async () => {
			const auth = new Auth({ apiKey: 'key' });
			fetch.mockResponse(`{ "users": [${JSON.stringify(mockUserData)}] }`);

			await mockLoggedIn(auth);
			await auth.fetchProfile();
			const storedData = JSON.parse(localStorage.getItem('Auth:User:key:default'));

			expect(storedData).toEqual(mockUserData);
		});

		test('Uses the tokenManager argument when its passed', async () => {
			const auth = new Auth({ apiKey: 'key' });

			fetch.mockResponse(`{ "users": [${JSON.stringify(mockUserData)}] }`);

			await auth.fetchProfile({ idToken: 'providedIdToken' });

			expect(fetch.mock.calls[0][1].body).toEqual('{"idToken":"providedIdToken"}');
		});
	});
});
