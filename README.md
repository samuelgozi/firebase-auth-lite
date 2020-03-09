# Firebase auth lite (WIP!)

The Official Firebase SDKs for Javascript are too big and can make it very hard for developers to achieve recommended loading times, and if you are like me and strive to provide the best performance for you users, its impossible to do on smartphones over 3G networks due to its big size.

I took it upon myself to provide an alternative SDK for when bad performance is just not an option. I'm currently working on libraries for Auth(this one), Firestore, and Storage.

The main goal of these libraries is to be as lean as possible, and provide close to full functionality, but if it comes at the cost of performance or size, I will most likely choose to stick to lower level functionality over features count. One example for that will be IE11 and browsers that don't support ES5. I wont try to support them because they require heavy pollyfils, and are dying anyways.

[My Alternative SDK performs in average 13 times better and is 27 times smaller than the official ones](https://github.com/samuelgozi/firebase-firestore-lite/wiki/Firebase-Alternative-SDK-Benchmarks).

## What else do I need to consider?

The API will not be identical or even close to the official one, but the core functionality will be the same.

Before you decide if this lib is for you please consider:

1. This is still work in progress!
2. Currently only Oauth authentication is supported(Take a look ath the roadmap for a more detailed list).
3. When adding a provider, or when using Google you will have to whitelist Redirect URLs manually(According to the OpenId Connect, thats how its supposed to be).
4. Sessions can only be persisted in localStorage(More options will be added).
5. Works only on browsers that support ES5, localStorage and Fetch API.
6. Not fully tested yet(I don't have a good testing strategy yet...)

## Is performance in the official JS SDK really that bad?

Short answer: yes. But the full answer is, that it depends on you project. If you want to know more details, please read my post on the Firebase google group: https://groups.google.com/forum/#!topic/firebase-talk/F0NenvOEYrE

## Roadmap
Progress towards 1.0 and features being added are tracked can be seen in [issue #2](https://github.com/samuelgozi/firebase-auth-lite/issues/2).

## How to install and use.

Before using it please note that its still work in progress.

```
npm install firebase-auth-lite
```

or

```
yarn add firebase-auth-lite
```

### How to set up

#### 1. Instantiate and add a provider.

```javascript
// auth.js

import { AuthFlow } from 'firebase-auth-lite';

const auth = new Auth({
	// Firebase apiKey, can be found in the config file.
	apiKey: '[API_KEY]',
	// Url that was whitelisted in the Federated Provider settings.
	// This is not a redirect for all individual logins, you can
	// configure that later.
	redirectUri: `http://localhost:123/auth`
});

// Add Google as an OAuth federated provider.
// You can use 'google', 'facebook', 'github' or 'twitter'.
// If Firebase supports one that is not in this list, open an issue,
// ill add it.
// You can add more info like "scope", read the docs below.
auth.addProvider({ provider: 'google' });

// Export it so that you can use the instance from other places.
export default auth;
```

There is one gotcha to using this library, when you add a Sign-in provider through the firebase console, you will need to manually add the redirect URL used in this step to that provider, instead(or in addition) to the `https://your-app.firebaseapp.com/__/auth/handler` that firebase asks you to add.

I considered fixing this, but it makes the sign in considerably slower, and you need to add the link provided by firebase anyways. The case in which firebase will automatically add their authorized URL is when using Google as a provider. And you can add it from the GCP console here:
https://console.developers.google.com/apis/credentials

Another reason I didn't fix this is because I believe its a little bit more secure when you have to add them explicitly. According to the OpenID connect standard, that is the reason for the existence of the restriction to only redirect to whitelisted domains.

#### 2. Begin authentication flow

This will usually be called when a user clicks a "sign in with [provider]" button, but feel free to do whatever you like.

```javascript
// Import the file we created above with the AuthFlow instance.
import auth from 'auth.js';

// Run this function when a user wants to log in.
function signIn() {
	// The first argument is the provider we want to use to sign in,
	// It has to be one that we configured, and we did configure one
	// in the file above, we added google.
	//
	// The second argument is where to redirect to after the log in.
	// Please note that this is not the same as what we passed in
	// the other file for the `AuthFlow` constructor.
	// The one there is used to finish the Oauth flow, and it has to
	// be whitelisted from the federated provider settings.
	auth.startOauthFlow('google', location.origin);
}

// For example on click on a button
document.getElementById('sign-in-with-google').addEventListener('click', signIn);
```

#### 3. Finish the auth flow

After the user clicked the sign-in button, and the `startOauthFlow` function ran, the user will be redirected to google, and will be asked to give permissions to the app.

If everything went OK and the user approved, he will then be redirected to the URL we provided when instantiating `AuthFlow`, if you remember that was `http://localhost:123/auth`.

So now in that route we need to run a function, and the user will be logged in.

```javascript
auth.finishOauthFlow();

// Now the user info is available and persisted with local storage.
console.log(auth.user);
```

If you provided a redirect URL in the previous step then the user will be redirected to it when the `finishOauthFlow` is called.

### One last thing, the last two steps can be combined.

You don't need to have a route just to run `finishOauthFlow`. It is possible to start and finish the auth flow in the same path this way:

```javascript
// Import the file we created above with the AuthFlow instance.
import auth from 'auth.js';

// Run this function when a user wants to log in.
function signIn() {
	// The first argument is the provider we want to use to sign in,
	// It has to be one that we configured, and we did configure one
	// in the file above, we added google.
	//
	// The second argument is where to redirect to after the log in.
	// Please note that this is not the same as what we passed in
	// the other file for the `AuthFlow` constructor.
	// The one there is used to finish the Oauth flow, and it has to
	// be whitelisted from the federated provider settings.
	auth.startOauthFlow('google', location.origin);
}

// For example on click on a button
document.getElementById('sign-in-with-google').addEventListener('click', signIn);

// Here we check if the URL has a search param named `code`
// It will be present on redirects from the Federated provider.
if (new URL(location.href).searchParams.has('code')) {
	auth.finishOauthFlow();
}
```

# Full API Reference

A full API reference will be written when most of the features will be done. But the current guide covers most of what is done al ready.
