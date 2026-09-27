# AiKya Play Store release checklist

## Completed in this workspace

- Android WebView wrapper under `android/` with portrait launcher activity.
- HTTPS-only WebView policy and user-controlled camera/microphone permissions.
- Installable web manifest, icons, and service-worker shell cache.
- Privacy policy, terms, and community content-policy pages.
- Firebase setup notes with authentication and Firestore rules.

## Required before public release

1. Create a real Firebase project and replace every `YOUR_*` value in `firebase-config.js`.
2. Enable Email/Password and Phone providers, configure SMS regions, authorized domains, App Check, Firestore, and Storage.
3. Move posts, profiles, messages, stories, and media from browser storage to authenticated Firestore/Storage collections. Do not use localStorage as the source of truth for production accounts.
4. Add Cloud Storage rules, moderation/report collections, abuse-rate limits, account deletion cleanup, and a server-side moderation process.
5. Replace placeholder support contact text in `privacy.html`, `terms.html`, and `content-policy.html` with a monitored email and a public privacy-policy URL.
6. Add a real Android signing key. Never commit the keystore or passwords. Configure release signing outside source control.
7. Install Android Studio and run `gradlew bundleRelease` from `android/`. Test the signed AAB on physical Android devices, including login, OTP, camera, microphone, uploads, playback, back navigation, offline behavior, account deletion, and permission denial.
8. Complete Play Console Data safety, content rating, target audience, ads declaration, app access instructions, privacy-policy URL, store listing, screenshots, and review contact details.
9. Test copyright and takedown handling for every video/movie source. Do not ship unlicensed movies or scraped YouTube content.

The current source is a release scaffold, not a finished public social network. A Play Store launch should wait until the Firebase project, server-backed content flows, moderation, legal contact, signed build, and device testing are complete.

Firebase web authentication also needs a hosted HTTPS origin listed in Firebase authorized domains. Do not expect phone OTP or reCAPTCHA to work reliably from a raw `file:///android_asset/` page; host the web app on Firebase Hosting or serve it through a controlled HTTPS origin before enabling production sign-up.
