# AiKya

AiKya is a dependency-free social app prototype combining a visual feed, stories, short-form clips, music posts, discovery trends, profiles, search, saved posts, and a working create-post flow.

## Run

Double-click `Start AiKya.bat`, or use `Open AiKya Direct.vbs` for a silent direct launch. `AiKya Console.bat` provides a small launcher menu for opening the app or project folder.

The current version stores interactions in the page session only. A production version would add authentication, a database, media uploads, notifications, moderation, and a real-time messaging backend.

## Movie and TV discovery

The Movies section uses TMDB for movie, TV-show, and animation metadata. Add a TMDB API key to `AiKya/firebase-config.js` by replacing `YOUR_TMDB_API_KEY`. The key is visible in a browser app, so production deployments should proxy TMDB requests through a backend and apply appropriate rate limits. AiKya links to JustWatch search results for legal viewing options; it does not host or stream those titles.

This product uses the TMDB API but is not endorsed or certified by TMDB.
