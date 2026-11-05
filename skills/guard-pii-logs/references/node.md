# Node: Express and NestJS

## pino

`redact` removes or replaces values at the listed paths before they are written.

```js
const logger = pino({
  redact: {
    paths: ['req.headers.authorization', 'req.headers.cookie', 'res.headers["set-cookie"]', '*.email', '*.phone'],
    censor: '[Redacted]',
  },
});
```

- Paths use dot and bracket syntax; `*` is a wildcard for one level (check the pino redaction docs for limits, such as wildcards not at the start of deeper paths, and for the performance note on redacting).
- `remove: true` drops the key instead of replacing it.
- pino-http (and nestjs-pino through its `pinoHttp` option) logs the request through pino's standard request serializer, which includes headers. Add header paths to `redact`, or use custom serializers that pick only what you need.
- Logging `{ req }` or `req.body` puts everything into the entry. Log `req.id` and `req.method`, and selected fields.

## winston

winston has no built-in redaction. Add a custom format that masks keys before output:

```js
const mask = winston.format((info) => {
  if (info.email) info.email = '[Redacted]';
  return info;
});
const logger = winston.createLogger({ format: winston.format.combine(mask(), winston.format.json()) });
```

A format only sees the entry object, so nested values need a recursive masker. Prefer not logging the value at all.

## Express

- `console.log(req.body)`, `logger.info(req.headers)`, `JSON.stringify(req)`: whole objects.
- Request loggers such as morgan can print headers or body tokens if you configure them to; review custom formats.
- `res.json(user)` returns every property of the object. Build the response from an allow-list (`pick`, a mapper function, a DTO).
- Error handlers that return `err` or `err.stack` to clients, or log `err` objects that carry the request (some HTTP clients attach request config including authorization headers to errors): log a message and a code instead.

## NestJS

- `class-transformer` with `ClassSerializerInterceptor`: mark properties `@Exclude()` on the entity or response class, or use `@Expose()` with the `strategy: 'excludeAll'` option of `@SerializeOptions`. The interceptor only applies if a class instance is returned, not a plain object.
- TypeORM columns accept `select: false`, so the column is not loaded unless asked for.
- Prisma returns all scalar fields by default. Use `select`, or the `omit` option where your Prisma version supports it, and map to response DTOs.
- Prefer separate response DTO classes over returning entities.
- The built-in `Logger` prints what you pass it; the same whole-object rules apply to `this.logger.log(...)`.

## Error tracking

@sentry/node: keep `sendDefaultPii` off unless needed, and scrub in `beforeSend`. See `trackers-analytics.md`.
