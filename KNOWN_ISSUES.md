# Known Issues

## stream.place iOS app OAuth flow fails

OAuth flow with stream.place's iOS app (using expo-web-browser's ASWebAuthenticationSession) does not complete. After user approves consent, the redirect from our PDS to stream.place's callback URL is not followed by ASWebAuthenticationSession.

What does work with stream.place: everything else :P
- Desktop browsers
- ios safari (regular browser)
- ASWebAuthenticationSession using the reference pds

What fails:
- ASWebAuthenticationSession with this pds

Attempted fixes (all failed):
- HTTP 302/303/307 redirects
- JavaScript navigation
- Meta refresh
- Form auto-submit
- Removing CORS headers
- HTTP/1.1 instead of HTTP/2
- Minimal response headers

