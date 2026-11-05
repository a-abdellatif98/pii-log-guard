# Error trackers and analytics

## Sentry options (all SDKs follow a similar shape; names differ by language, check your SDK docs)

| Option | Effect | Guidance |
|---|---|---|
| `sendDefaultPii` (JS), `send_default_pii` (Python, Ruby, PHP) | Adds data such as cookies, user ip and request headers | Leave off; if on, scrub in a hook |
| `beforeSend` (JS), `before_send` (Python, Ruby, PHP) | Hook to edit or drop an event | Use it to remove request bodies, cookies and user fields |
| Request body size (`max_request_body_size` in Python; some JS server SDKs have a similar option) | How much of a request body is attached | Prefer `never`/off for endpoints that take personal or secret input |
| `setUser` / `set_user` | Attaches a user to events | Send an opaque id, not an email or phone number |

Server-side scrubbing rules and "data scrubbing" settings in the Sentry project are a second layer. They are not a reason to send the data.

Other trackers (Bugsnag, Rollbar, Honeybadger, Datadog): each has a parameter filter list or a scrubbing hook. The same questions apply: does it attach the request body, headers, cookies or user identity, and is there a filter list that covers your sensitive names.

## Analytics

- `identify` and `track` calls (Segment, Mixpanel, Amplitude, PostHog, Ahoy and similar) should carry an opaque user id and non-identifying traits.
- Email or phone as a trait or an event property sends it to a third party and into its exports. If the product needs it, document the legal basis and hash only when the tool requires hashing; hashing an email is still personal data.
- Event names built by interpolating user input leak data into the event stream.
- Check autocapture features (session replay, form field capture): mask inputs of sensitive type and add masking classes to sensitive elements, following the tool's docs.

## Log shipping

Logs shipped to a hosted service are copied outside your system. Redact before shipping (in the app) rather than relying on a pipeline rule you may forget to deploy. Retention matters: shorter retention reduces exposure.

## Verification

Add a test that sends a request containing a marker value in a sensitive field, captures log output and tracker payloads (a test transport or a stubbed client), and asserts the marker is absent.
