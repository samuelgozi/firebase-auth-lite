import Auth from '../src/main.js';

const mockUserData = {
	tokenManager: {
		idToken: 'idTokenString',
		expiresAt: Date.now()
	}
};

describe('localStorageAdapter()', () => {
	const auth = new Auth({ apiKey: 'test' });

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
				fetch.resetMocks();
				fetch.mockResponse('{"users": [{}]}');

				localStorage.setItem('Auth:User:key:default', JSON.stringify(mockUserData));
				const auth = new Auth({ apiKey: 'key' });

				await new Promise(resolve => {
					auth.listen(resolve);
				});

				expect(auth.user).toEqual(mockUserData);
				localStorage.removeItem('Auth:User:key:default');
			});

			test('Updates the stored data if the user is logged in', async () => {
				// The constructor makes some requests.
				// We have to mock them for this not to throw
				fetch.resetMocks();
				fetch.mockResponse('{"users": [{ "username": "updated!" }]}');

				localStorage.setItem('Auth:User:key:default', JSON.stringify(mockUserData));
				const auth = new Auth({ apiKey: 'key' });

				// Await for the first update to happen.
				const userData = await new Promise(resolve => {
					auth.listen(resolve);
				});

				expect(auth.user.username).toEqual('updated!');
				expect(userData).toEqual(auth.user);
				localStorage.removeItem('Auth:User:key:default');
			});
		});

		test("Doesn't make any requests when the user is not logged in", async () => {
			// The constructor makes some requests.
			// We have to mock them for this not to throw
			fetch.resetMocks();
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
			fetch.resetMocks();
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
			localStorage.removeItem('Auth:User:key:default');
		});

		test('Updates the "user" property with the new data', async () => {
			const auth = new Auth({ apiKey: 'key' });
			await auth.persistSession({ test: 'working' });

			expect(auth.user).toEqual({ test: 'working' });

			// Cleanup
			localStorage.removeItem('Auth:User:key:default');
		});

		test('Fires an event', async () => {
			const auth = new Auth({ apiKey: 'key' });

			const callback = jest.fn(() => {});
			auth.listen(callback);

			await auth.persistSession();

			expect(callback).toHaveBeenCalledTimes(1);

			// Cleanup
			localStorage.removeItem('Auth:User:key:default');
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
});
