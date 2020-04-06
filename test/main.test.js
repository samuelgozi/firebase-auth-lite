import Auth from '../src/main.js';

const mockUserData = {
	email: 'test@example.com',
	tokenManager: {
		idToken: 'idTokenString',
		expiresAt: Date.now() + 3600 * 1000 // In one hour from now.
	}
};

afterEach(() => {
	fetch.resetMocks();
	localStorage.removeItem('Auth:User:key:default');
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

	test('delete() removes an item from local storage', async () => {
		await auth.storage.remove('testKey');
		expect(localStorage.getItem('testKey')).toEqual(null);
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

		test('Throws when providers is not an array', () => {
			expect(() => {
				new Auth({ apiKey: 'key', providers: {} });
			}).toThrow('The argument "providers" must be an array');

			expect(() => {
				new Auth({ apiKey: 'key', providers: 42 });
			}).toThrow('The argument "providers" must be an array');
		});

		describe('Initializes the "user" property', () => {
			test('Reads the username from storage when already logged in', async () => {
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

			test('Updates the stored data if the user is logged in', async () => {
				// The constructor makes some requests.
				// We have to mock them for this not to throw
				fetch.mockResponse('{"users": [{ "username": "updated!" }]}');

				localStorage.setItem('Auth:User:key:default', JSON.stringify(mockUserData));
				const auth = new Auth({ apiKey: 'key' });

				// Await for the first update to happen.
				const userData = await new Promise(resolve => {
					auth.listen(resolve);
				});

				expect(auth.user.username).toEqual('updated!');
				expect(userData).toEqual(auth.user);
			});
		});

		test("Doesn't make any requests when the user is not logged in", async () => {
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

	describe('enforceAuth()', () => {
		test('Throws when the user is not logged in', async () => {
			const auth = new Auth({ apiKey: 'key' });
			await expect(auth.enforceAuth()).rejects.toThrow('The user must be logged-in to use this method.');
		});

		test("Doesn't make any requests when the user is not logged in", async () => {
			// The constructor makes some requests.
			// We have to mock them for this not to throw
			fetch.mockResponse('{}');

			try {
				const auth = new Auth({ apiKey: 'key' });
				await auth.enforceAuth();
			} catch {}

			expect(fetch.mock.calls.length).toEqual(0);
		});
	});

	describe('perssistSession()', () => {
		test('Stores the user data locally', async () => {
			const auth = new Auth({ apiKey: 'key' });
			await auth.persistSession({ test: 'working' });

			expect(await auth.storage.get('Auth:User:key:default')).toEqual(JSON.stringify({ test: 'working' }));

			// Cleanup
		});

		test('Updates the "user" property with the new data', async () => {
			const auth = new Auth({ apiKey: 'key' });
			await auth.persistSession({ test: 'working' });

			expect(auth.user).toEqual({ test: 'working' });

			// Cleanup
		});

		test('Fires an event', async () => {
			const auth = new Auth({ apiKey: 'key' });

			const callback = jest.fn(() => {});
			auth.listen(callback);

			await auth.persistSession();

			expect(callback).toHaveBeenCalledTimes(1);

			// Cleanup
		});
	});

	describe('signOut()', () => {
		test('Deletes user data from storage', async () => {
			const auth = new Auth({ apiKey: 'key' });

			// Mock logged in user.
			await auth.persistSession('test');

			// sign out.
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

			expect(callback).toHaveBeenCalledTimes(1);
		});
	});

	describe('refreshIdToken()', () => {
		test('Returns if token is still valid', async () => {
			// The constructor makes some requests.
			// We have to mock them for this not to throw
			fetch.mockResponse('{"users": [{ "updated": true }]}');

			const auth = new Auth({ apiKey: 'key' });
			// Mock logged in user.
			auth.user = mockUserData;

			await auth.refreshIdToken();

			expect(fetch.mock.calls.length).toEqual(0);
		});

		test('Allow only one concurrent fetch request', async () => {
			// The constructor makes some requests.
			// We have to mock them for this not to throw
			fetch.mockResponse('{"users": [{ "updated": true }]}');

			const auth = new Auth({ apiKey: 'key' });
			// Mock logged in user.
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
			const responseDate = new Date();

			fetch.mockResponse('{"users": [{ "updated": true }]}', {
				headers: {
					date: responseDate.toUTCString()
				}
			});

			const auth = new Auth({ apiKey: 'key' });
			// Mock logged in user.
			auth.user = {
				tokenManager: {
					idToken: 'idTokenString',
					// Mock old expiration time
					expiresAt: Date.now() - 1000
				}
			};

			const expectedExpiration = new Date(responseDate + 3600 * 1000);
			await auth.refreshIdToken();

			// Check that the time is close enough by allowing
			// a few milliseconds of delay, since the function takes time to run.
			expect(new Date(auth.user.tokenManager.expiresAt)).toEqual(expectedExpiration);
		});

		test('Updates id and refresh tokens', async () => {
			// The constructor makes some requests.
			// We have to mock them for this not to throw
			fetch.mockResponse('{"refresh_token": "updated", "id_token": "updated"}');

			const auth = new Auth({ apiKey: 'key' });

			// Mock logged in user.
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
	});

	describe('AuthorizedRequest()', () => {
		test('Adds Authorization headers when the user is logged in.', async () => {
			// The constructor makes some requests.
			// We have to mock them for this not to throw
			fetch.mockResponse('{}');

			const auth = new Auth({ apiKey: 'key' });
			// Mock logged in user.
			auth.user = mockUserData;

			await auth.authorizedRequest('http://google.com');

			const headers = fetch.mock.calls[0][0].headers;

			expect(headers.get('Authorization')).toEqual('Bearer idTokenString');
		});

		test("Doesn't change the request when the user is not logged in", async () => {
			// The constructor makes some requests.
			// We have to mock them for this not to throw
			fetch.mockResponse('{}');

			const auth = new Auth({ apiKey: 'key' });

			const request = new Request('http://google.com');
			await auth.authorizedRequest(request);

			expect(fetch.mock.calls[0][0]).toBe(request);
		});
	});

	describe('signInWithCustomToken', () => {
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

	describe('signUp', () => {
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

	describe('signIn', () => {
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

	describe('senbOobCode', () => {
		test('Throws when request type is "verify email" but not logged in', async () => {
			const auth = new Auth({ apiKey: 'key' });
			await expect(auth.sendOobCode('VERIFY_EMAIL')).rejects.toThrow();
		});

		test('Sends correct request to "verify email"', async () => {
			const auth = new Auth({ apiKey: 'key' });
			auth.user = mockUserData;

			fetch.mockResponse('{}');
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
			auth.user = mockUserData;
			fetch.mockResponse('{}');
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

	describe('resetPassword', () => {
		test('Sends the correct request', async () => {
			const auth = new Auth({ apiKey: 'key' });
			auth.user = mockUserData;

			fetch.mockResponse('{}');
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
			auth.user = mockUserData;

			fetch.mockResponse('{}');
			await auth.resetPassword('code');

			expect(fetch.mock.calls[0][1].body).toEqual('{"oobCode":"code"}');
		});

		test('Returns the email of the account', async () => {
			const auth = new Auth({ apiKey: 'key' });
			auth.user = mockUserData;

			fetch.mockResponse('{ "email": "test@mail.com" }');
			const response = await auth.resetPassword('code', 'password');

			expect(response).toEqual('test@mail.com');
		});
	});
});
