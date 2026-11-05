# Django

## Error reports and debug pages

`django.views.decorators.debug` provides two decorators that keep values out of error reports (the debug page and the emails or handlers that use the default exception reporter filter):

```python
from django.views.decorators.debug import sensitive_post_parameters, sensitive_variables

@sensitive_variables("card_number", "cvv")
def charge(card_number, cvv):
    ...

@sensitive_post_parameters("card_number", "cvv")
def checkout(request):
    ...
```

- `sensitive_variables()` with no arguments hides every local variable of that function in reports. With names, only those. When stacking decorators, put it at the top of the chain (per the Django docs).
- `sensitive_post_parameters()` with no arguments hides all POST parameters; with names, only those. Apply it to the view function.
- These protect error reports. They do not stop `logger.info(request.POST)` in your own code.
- The reporter filter class can be replaced through the `DEFAULT_EXCEPTION_REPORTER_FILTER` setting for project-wide rules (subclass `SafeExceptionReporterFilter`; check the docs for your version).
- Never run production with debug mode on: the debug page renders settings and local variables.

## Logging

- Attach a `logging.Filter` to handlers to mask known patterns, or avoid passing sensitive objects at all. A filter is a safety net; the fix is to not log the value.
- `logger.info(request.POST)`, `print(request.data)`, `logger.info("user %s", request.user)` (the user's string form can be an email), `logging.debug(locals())`, `vars(user)`: whole objects.
- Use `request.user.pk` for identity in logs.
- `django.request` and `django.server` loggers can include request details at some levels; review handler levels.

## Serializers and responses

- Django REST framework: `fields = "__all__"` exposes every model column, including ones added later. List fields explicitly.
- Mark input-only fields `write_only=True` (or `extra_kwargs = {"field": {"write_only": True}}`).
- Use separate serializers per audience (owner, staff, public) instead of one serializer with many conditionals.
- `model_to_dict(user)` and `JsonResponse(user.__dict__)` return all fields.
- Django admin and `ModelForm` with `fields = "__all__"` have the same all-fields problem for editing.

## Error tracking

sentry-sdk for Python: `send_default_pii` defaults to off; keep it off or scrub with `before_send`. `max_request_body_size` controls how much of a request body is attached (values include `"never"`, `"small"`, `"medium"`, `"always"`; check the SDK docs for your version). The SDK has a default event scrubber with a denylist that can be extended (`sentry_sdk.scrubber.EventScrubber`; check the docs for your version). See `trackers-analytics.md`.
