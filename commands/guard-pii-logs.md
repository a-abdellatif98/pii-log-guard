---
description: Find code that leaks personal or secret data into logs, error reports, analytics and API responses, and propose the filter, redaction or serializer fix
argument-hint: [path, controller/serializer name, or description]
allowed-tools: [Read, Glob, Grep]
---

# Guard PII in Logs and Responses

Find places where personal or secret data can end up in logs, error trackers, analytics or API output, following the `guard-pii-logs` skill.

## Arguments

The user invoked this command with: $ARGUMENTS

Treat the argument as a path, a controller, serializer, job or logger name, or free text. If it is empty, ask which area to inspect, or default to the app code directories (`app/` for Rails and Laravel, the Django app folders, `src/` for Node).

## Instructions

1. **Detect the framework** with Glob: Rails (`Gemfile`, `app/controllers`), Django (`manage.py`), Laravel (`composer.json`, `app/Models`), Node (`package.json`, NestJS modules or Express routes).

   Never open environment files, database config, credential files, key files, Django settings modules, or anything holding tokens, passwords or connection strings. Read application code only. If a setting you need lives in one of those files, ask the user to paste only the relevant non-sensitive lines.

2. **Check the global safety nets** using `skills/guard-pii-logs/references/` (`rails.md`, `django.md`, `laravel.md`, `node.md`, `trackers-analytics.md`): parameter filtering, log redaction, hidden model attributes, error tracker options.

3. **Find the leaks in code**: log calls that pass a whole request, params, headers or user object; log calls that interpolate personal or secret fields; tracker and analytics calls carrying identifiers such as emails or phone numbers; serializers, resources and `render json` calls that expose whole records or sensitive fields.

4. **Trace before concluding**: follow the value to where it is built and check whether a filter, mask or serializer already protects it. A field that is intended for its owner may be fine; say who the audience is.

5. **Propose the fix** in the project's framework as code, with its cost (lost debug detail, a migration of existing log shipping rules).

## Output format

### PII findings: `target`

**Detected:** framework, logger, error tracker and analytics in use.

**Findings:** numbered, each with `file:line`, what leaks, where it lands (log, tracker, analytics, response) and the fix as code. Tag each `high` or `medium`.

**Safety nets:** filter and redaction settings that exist, and the ones missing.

**Not a problem:** hits you checked that are masked, filtered or intended for the owner (say why).

**Scanner:** mention that `python3 scripts/pii_scan.py <project root>` (run from the plugin directory by the user) gives a heuristic first pass, exit code 1 when it finds something, and never prints source lines. It is heuristic: confirm each hit.

Do not run anything. Read code, produce findings and diffs only.
