# Firebase setup for AiKya

1. Create a Firebase project in the Firebase Console.
2. Add a web app and copy the config values into `firebase-config.js`.
3. Enable Email/Password sign-in in Authentication.
4. Enable Phone sign-in and configure SMS regions for OTP.
5. Enable Firestore Database and Storage.
6. Add security rules for users, posts, and media.

Example Firestore rules:

```js
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
    match /posts/{postId} {
      allow read: if request.auth != null;
      allow create: if request.auth != null && request.resource.data.authorId == request.auth.uid;
      allow update, delete: if request.auth != null && resource.data.authorId == request.auth.uid;
    }
  }
}
```

Example Firebase Auth email/password flow is already wired in `app.js`.

For production, replace the placeholder values in `firebase-config.js` with the real Firebase project values. Configure Storage rules, App Check, authorized domains, abuse reporting, and a monitored support email before release.
