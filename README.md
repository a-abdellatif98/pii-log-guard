# pii-log-guard

A plugin that finds code leaking personal or secret data into logs, error reports, analytics and API responses, for Rails, Django, Laravel and Node (Express and NestJS).

It pairs with [db-migration-guard](https://github.com/a-abdellatif98/db-migration-guard) (safe schema changes), [backfill-planner](https://github.com/a-abdellatif98/backfill-planner) (safe data jobs) and [n-plus-one-hunter](https://github.com/a-abdellatif98/n-plus-one-hunter) (query patterns).

## What it looks for

- **Whole objects in log calls**: params, requests, headers, bodies, user records
- **Sensitive fields in log calls**: emails, phone numbers, access tokens, card data
- **Missing safety nets**: Rails `filter_parameters`, Django `sensitive_post_parameters` and `sensitive_variables`, Laravel `$hidden` and `$dontFlash`, pino `redact`
- **Error trackers**: default PII, request bodies, user context with personal data
- **Analytics**: identify and track calls that carry personal data
- **Serializers**: whole records rendered as JSON, all-fields serializers, sensitive fields in resources, entities without `@Exclude()`

## Installation

```
/plugin install pii-log-guard@claude-plugins-official
```

## Usage

### Slash command

```
/guard-pii-logs app/controllers/sessions_controller.rb
/guard-pii-logs our API responses leak too much
```

It reads application code with read-only tools and outputs numbered findings with the sink, the data category and the fix as code. It never opens environment files, database config, credential files or key files.

### Skill

The `guard-pii-logs` skill activates when you talk about PII in logs, redaction, parameter filtering, tracker options or serializer exposure. References:

| Reference | Covers |
|---|---|
| `rails.md` | `filter_parameters`, `filter_attributes`, job argument logging, serializers |
| `django.md` | `sensitive_post_parameters`, `sensitive_variables`, logging filters, DRF `fields` and `write_only` |
| `laravel.md` | `$hidden`, `$visible`, API resources, `$dontFlash`, Telescope |
| `node.md` | pino `redact`, winston formats, Express responses, NestJS `@Exclude()` and `ClassSerializerInterceptor` |
| `trackers-analytics.md` | Sentry options, analytics traits, log shipping, leak tests |

### Static scanner

```
python3 scripts/pii_scan.py path/to/project
python3 scripts/pii_scan.py --json --min-severity high app/
```

Exit code 0 when clean, 1 when it finds something, 2 for a bad path. It is heuristic: confirm each hit. Suppress a reviewed line with a comment containing `pii: ok`.

Safety properties of the scanner:

- Python standard library only. It opens no network connection, starts no subprocess and reads source files only.
- It prints the file, line, rule code and a fixed message, never the source line, so a finding cannot echo a secret.
- It only opens source files with a known extension (Ruby, Python, PHP, JavaScript, TypeScript). It refuses every other file, including hidden files, settings modules and database config. Config folders are skipped, except the Rails initializers folder.
- It skips symlinks, files over 1 MB, dependency folders and (unless `--include-tests`) test folders.

Rule codes: `PII-LOG-OBJECT`, `PII-LOG-FIELD`, `PII-TRACKER-PII`, `PII-TRACKER-BODY`, `PII-TRACKER-USER`, `PII-ANALYTICS`, `PII-SERIALIZER-WHOLE`, `PII-SERIALIZER-ALL`, `PII-SERIALIZER-FIELD`, `PII-RAILS-NOFILTER`, `PII-DJANGO-NOSENSITIVE`, `PII-LARAVEL-NOHIDDEN`, `PII-NODE-NOREDACT`, `PII-NEST-ENTITY`.

## Limits

Heuristics read one line at a time. The Rails check only confirms that the standard initializer sets some `filter_parameters` list, not that the list is complete. Multi-line calls, values passed through helper functions and filters configured outside the standard places are not seen. Framework option names change between versions: the references hedge where it matters.

## License

MIT
