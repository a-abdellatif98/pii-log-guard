# Laravel

## Hidden model attributes

Attributes listed in the model's `$hidden` array are removed when the model is converted to an array or JSON (`toArray`, `toJson`, returning a model from a route). `$visible` is the allow-list alternative. `makeHidden([...])` and `makeVisible([...])` adjust per call.

```php
class User extends Authenticatable
{
    protected $hidden = ['password', 'remember_token', 'two_factor_secret'];
}
```

- Review every model that mass-assigns secret-looking attributes: if there is no `$hidden` or `$visible` list, a returned model exposes them.
- `$hidden` affects serialization. It does not stop `Log::info($user->getAttributes())` or `->getRawOriginal()` from printing values.
- Prefer API Resources (`JsonResource`) with an explicit `toArray` for responses, and `$this->when(...)` or `whenLoaded(...)` for conditional fields. Do not `return parent::toArray($request)` on a model with sensitive columns unless the model hides them.

## Flashed input on validation errors

Failed validation flashes the submitted input to the session so forms can repopulate. Names listed in `$dontFlash` on the exception handler class are excluded (older application skeletons). Newer skeletons configure it in the application bootstrap file with `$exceptions->dontFlash([...])`. Check where your version keeps it. Default lists cover password fields; add card and token style inputs.

## Logging patterns to flag

- `Log::info($request->all())`, `Log::debug(request()->all())`, `logger($request->input())`, `dd($request)` left in code, `print_r($request)`: whole inputs.
- `Log::info($user->toArray())`: everything not hidden, and `$hidden` does not apply to a plain `getAttributes()`.
- `Log::info("phone {$user->phone}")`: named personal field. Log `$user->id`.
- Use `Log::withContext([...])` carefully: context is attached to every later entry.
- Query logging (`DB::listen`, `DB::enableQueryLog`) records bound values.

## Telescope and debug tools

If Laravel Telescope is installed, hide request parameters and headers with `Telescope::hideRequestParameters([...])` and `Telescope::hideRequestHeaders([...])` (check the docs for your version) and keep it off or gated in production. The debug page and Ignition show request data when debug mode is on; never enable debug mode in production.

## Error tracking

sentry-laravel: the `send_default_pii` option in its configuration file defaults to off. Keep it off, or scrub with `before_send`. See `trackers-analytics.md`.
