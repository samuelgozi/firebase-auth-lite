import Auth from '../src/main.js';

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
