# Firebase auth lite (Beta) [![codecov](https://codecov.io/gh/samuelgozi/firebase-auth-lite/branch/master/graph/badge.svg)](https://codecov.io/gh/samuelgozi/firebase-auth-lite) ![bundlephobia](https://badgen.net/bundlephobia/minzip/firebase-auth-lite)

A performance focused alternative to the official firebase auth library that is designed to work with my other alternatives for [storage](https://github.com/samuelgozi/firebase-storage-lite) and [firestore](https://github.com/samuelgozi/firebase-firestore-lite).

The goal of this library is to provide a performance focused alternative to the official SDKs. This comes with some costs. The big one is browser support, we only support modern browsers, but you can always run them through Babel.

[My Alternative SDK performs in average 13 times better and is 27 times smaller than the official ones](https://github.com/samuelgozi/firebase-firestore-lite/wiki/Firebase-Alternative-SDK-Benchmarks).

## What else do I need to consider?

The API is completely different. This is not a drop-in replacement, instead our API is much simpler and easier to use.
In addition you should consider the next points:

1. This is still work in progress and the API will change without warning until version 1.0.
2. There is a small difference working with Federated Identity Providers.
3. Sessions can only be persisted in localStorage (More options will be added).
4. The code is written with modern JS and you are responsible for transpiling it for your targets, but babelrc configuration is ready. The code also makes use of the Fetch API and local storage.
5. Not fully tested yet(I don't have a good testing strategy yet...)

## Features and roadmap

- [x] Authenticate with Email and password.
- [x] Authenticate with Federated Identity Provider.
- [x] Authenticate with link to email (no password required).
- [x] Authenticate with a custom token.
- [x] Authenticate anonymously.
- [ ] Authenticate with phone.

- [x] "Upgrade" anonymous accounts to any of the other ones.

- [x] List all providers associated with an Email.
- [x] Update Profile
- [x] Reset password
- [x] Verify email
- [x] Delete the account.

The roadmap and progress to 1.0 can be seen at [issue #2](https://github.com/samuelgozi/firebase-auth-lite/issues/2).

## Setting up Federated identity providers

You might have noticed that when adding a Oauth Sign-in method in the firebase console, you are asked to add a URL that looks something like this to the Oauth's configurations: `https://[app-id].firebaseapp.com/__/auth/handler`

What you are essentially doing is whitelisting that URL, which is a hidden URL that exists in every firebase app. When using this library, you will need to add the URL of **your app** instead of the firebase's one. You need to add the URL of the page in your app that will handle the log in. You'll see what I mean in the docs below.

You might be curious as to why I'm avoiding using firebases endpoint, well, the reasons are:

1. It is more secure. The reason you need to whitelist in the first place is for security.
2. It is way faster, in some cases up to 5 seconds faster.
3. I don't trust firebase (or anyone) with my user's private data, and you shouldn't either.

Yes, I know that the third one sounds exaggerated, especially when we rely on them anyways. But their endpoint works on the client (It's JS) and you shouldn't trust the client.

## How to install

Once again i will say that its all still work in progress. Some things might break, and the API might change.
However, I do encourage anyone to try it. I need feedback in order to improve it, so please use it and don't hesitate to leave feedback!

```
npm install firebase-auth-lite
```

or

```
yarn add firebase-auth-lite
```

After adding it to your dependencies instantiate.

```js
import Auth from 'firebase-auth-lite';

// The multiple options can be seen in the API Reference,
// but only the apiKey is required across all auth flows.
const auth = new Auth({
	apiKey: '[The Firebase API key]'
});
```

### Authenticate with email and password.

First instantiate Auth.

```js
import Auth from 'firebase-auth-lite';

const auth = new Auth({
	apiKey: '[The Firebase API key]'
});
```

Then to sign-up use the `signUp` method.
Please note that after a sign up, the user will be signed in automatically.

```js
// Pass a new email and password.
auth.signUp('email', 'password');
```

In order to sign-in, pass the email and password to the `signInWithPassword` method.

```js
auth.signIn('email', 'password');
```

If the data is correct and matches an existing user, the user will be signed in. Else, an error will be thrown with an explanation as to why.

### Authenticate with Federated Identity Provider.

When signing in with an IdP, the user will be redirected to their page, and later redirected back into our app. Because of this, we need to tell the provider where to redirect to by using the `redirectUri` property. It needs to be a page that will finish the sign in flow by running a method (read below how).

Please make sure the provider is correctly set up in the Firebase console.

```js
const auth = new Auth({
	apiKey: '[The Firebase API key]',
	redirectUri: 'http://example.com/auth'
});

// This function will run when the user click the sign in button.
function handleSignIn() {
	// This function will redirect the user out of our site, and into
	// the providers auth site. When the user finishes, he will then be
	// redirected into the `redirectUri` we have set in the `auth` instance.
	auth.signInWithProvider('google.com');
}

// Listen for the click, and run the sign in function.
document.getElementById('sign-in-google').addEventListener('click', handleSignIn);
```

The user will be redirected to `http://example.com/auth`, we need to make sure that we whitelisted this URL in the provider's settings. If not, we will receive an error with instructions on how to do so from the provider.

In that URL we need to finish the auth flow. We do that very easily by running a function. You can even do it on the same page you redirected from.

### Authenticate with magic link (Email link).

To be able to do this, we need to send an OobCode to the users email, and then handle the user click on the link received.

```js
const auth = new Auth({
	apiKey: '[The Firebase API key]',
	redirectUri: 'http://example.com/auth'
});

function loginWithEmail() {
	const email = document.getElementById('email-input').value;
	// We need to store somewhere the user email localy in order to validate that is the same user who clicked the email than the one who requested the email
	window.localStorage.setItem('loginEmail', email);

	// Then we request the email to be sent to the user
	auth.sendOobCode('EMAIL_SIGNIN', email)
}

// Listen for the click, and run the sign in function.
document.getElementById('sign-in').addEventListener('click', loginWithEmail);
```

In the email the user will receive an email who will redirect him to our previously defined redirectUri, in this case `http://example.com/auth`, we need to make sure that we whitelisted this URL in the provider's settings. If not, we will receive an error with instructions on how to do so from the provider.

In that URL we need to finish the auth flow. We do that very easily by running a function. You can even do it on the same page you redirected from.

```js
async handleRedirect() {
	try {
		await auth.handleSignInRedirect({
			email: window.localStorage.getItem('loginEmail'),
		});
		window.localStorage.removeItem('loginEmail');

		// Do whatever you want with the newly logged in user
	} catch (error) {
		console.error(error);
	}
}
```

### Authenticate anonymously.

You can authenticate a user anonymously with the same method used for email and password, just don't pass any arguments.

```js
const auth = new Auth({
	apiKey: '[The Firebase API key]'
});

// That's all, really.
auth.signUp();
```

## Listening for state changes

When working with reactive frameworks/libraries you will want to be able to tell when the user's data was updated.
Its very easy to do with this library.
in order to listen to state changes just call `listen()` with a callback:

```js
const removeListener = auth.listen(user => {
	console.log(user); // Will log the user object.
});

removeListener(); // The callback will no longer be called on updates.
```

Now every time the user state or data is changed, the callback will be called with the new data.
The `listen()` method returns a function that can be called when we wish to stop listening for updates.

# Full API Reference

There are many more features, and they can be discovered by reading the full API reference. It can be found here:
https://github.com/samuelgozi/firebase-auth-lite/wiki/API-Reference
