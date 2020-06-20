export const localStorageAdapter = {
	async set(k, v) {
		window.localStorage['setItem'](k, v);
	},
	async get(k) {
		return window.localStorage.getItem(k);
	},
	async remove(k) {
		window.localStorage.removeItem(k);
	}
};
