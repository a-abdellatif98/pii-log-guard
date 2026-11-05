---
name: guard-pii-logs
description: This skill should be used when the user asks whether code leaks personal or secret data, or mentions "PII in logs", "sensitive data in logs", "log redaction", "filter_parameters", "sensitive_post_parameters", "sensitive_variables", "dontFlash", "hidden attributes", "pino redact", "send_default_pii", "Sentry request body", "scrub", "mask", "GDPR logging", "serializer exposes email", "API leaks fields", or when reviewing logging, error reporting, analytics or serializer code in a Rails, Django, Laravel or Node (Express, NestJS) app.
version: 1.0.0
---

# Guard PII in Logs and Responses

Personal data (emails, phone numbers, addresses, national ids) and secrets (passwords, access tokens, session cookies, card data) end up in places they should not be: log files, error reports, analytics events and API responses. Logs are retained, shipped to third parties and read by many people, so a leak there is hard to undo.

## Where leaks come from

1. **Whole objects in log calls.** Logging `params`, a request, its headers or body, or a user record prints every field, including ones nobody thought about.
2. **Named sensitive fields in log calls.** A message that interpolates an email, a token or a card number.
3. **Missing global filtering.** The framework can scrub known parameter names from request logs and error pages, but only if configured (see the framework references).
4. **Error trackers.** Options that attach request bodies, cookies, headers or the user's ip and identity to every event.
5. **Analytics.** Identify and track calls that send an email or phone number as a trait or event property.
6. **Serializers and responses.** A whole record rendered as JSON, "all fields" serializers, resources that list sensitive fields for every audience.
7. **Hidden channels.** Job argument logging, exception messages that embed values, debug pages, query logs with bound values.

## Workflow

1. **Detect the stack**: framework, logger, log shipper, error tracker, analytics. Read application code only, never environment files, database config, credential files or key files.
2. **Check the safety nets** for the framework (`references/`). A missing net is a finding by itself.
3. **Find the sinks**: grep log calls, tracker and analytics calls, serializers and `render json` calls. For each, trace the value back to where it is built.
4. **Classify** by what leaks and where it lands. A secret in a log is worse than an email in a response meant for its owner. Name the audience for every response finding.
5. **Fix at the right layer**: prefer one global filter or redaction rule over many call-site edits, then fix call sites that log whole objects. Prefer opaque ids (`user.id`) over identifying values.
6. **Guard it**: add a test that logs a request containing a marker value and asserts the marker is absent from the output, and run `scripts/pii_scan.py` in review.

## Choosing the fix

| Leak | Rails | Django | Laravel | Node |
|---|---|---|---|---|
| Request params in logs | `filter_parameters` | `sensitive_post_parameters` for error reports, a logging filter for logs | `$dontFlash`, telescope hiding if used | pino `redact`, custom winston format |
| Whole user in log | log `user.id` | log `request.user.pk` | log `$user->id` | log `user.id` |
| Fields in JSON | serializer with explicit attributes | serializer `fields` list, `write_only` | `$hidden` and API resources | `@Exclude()` with `ClassSerializerInterceptor`, explicit DTOs |
| Tracker data | `send_default_pii` off, `before_send` | `send_default_pii` off, `before_send` | `send_default_pii` off | `sendDefaultPii` off, `beforeSend` |

Details per framework: `references/rails.md`, `references/django.md`, `references/laravel.md`, `references/node.md`, `references/trackers-analytics.md`.

## Rules for the report

- Never print the leaked value itself in the report. Cite `file:line` and the field name.
- A finding states the sink (log, tracker, analytics, response), the data category, and the fix.
- Mark what was not traced. If a filter might exist in a file you did not open, say so as a question.
- Many "hits" are masked or intended for the owner: list them under "Not a problem" with the reason.
- Frameworks change option names between versions. When recommending an option, hedge with "check the docs for your version" if you did not see it used in this project.
