# Rails

## Parameter filtering

`config.filter_parameters` lists parameter names whose values are replaced with `[FILTERED]` in the request log. New apps get an initializer at `config/initializers/filter_parameter_logging.rb`. Recent generated templates ship a list of partial names such as `:passw`, `:secret`, `:token`, `:_key`, `:crypt`, `:salt`, `:certificate`, `:otp`, `:ssn` (newer versions add more, for example `:email`, `:cvv`, `:cvc`; check the template for your Rails version).

```ruby
Rails.application.config.filter_parameters += [:email, :phone, :card_number, :iban]
```

- Symbols match as partial, case-insensitive substrings of the parameter name, so `:token` also filters `access_token`. Nested names can be written as a path with dots, for example `"user.address"` (check the guide for your version).
- A proc or regexp entry is also accepted for custom rules.
- `filter_parameters` also scrubs `ActiveSupport::ParameterFilter` users: the same class can scrub your own hashes before logging: `ActiveSupport::ParameterFilter.new(Rails.application.config.filter_parameters).filter(hash)`.
- Setting the list to empty, or `clear`, turns filtering off. That is a finding.
- Filtering applies to the request log line and to error pages. It does not stop `logger.info(params)` in your own code from printing values unless the value passes through the filter.

## Model inspection

`ActiveRecord::Base.filter_attributes` controls which attributes show as `[FILTERED]` in `inspect`, for example when a record is interpolated in a log message or error.

```ruby
class User < ApplicationRecord
  self.filter_attributes += [:email, :phone]
end
```

By default it follows `filter_parameters` (Rails 6 and later; check your version).

## Logging patterns to flag

- `Rails.logger.info(params)`, `logger.debug(request.headers.inspect)`, `puts current_user.inspect`: whole objects.
- `logger.info "login #{user.email}"`: named personal field. Log `user.id`.
- `rescue => e; logger.error(e.message)` where the message embeds a record or query string. Trace what builds the message.
- Active Job logs arguments. For jobs whose arguments are sensitive, set `self.log_arguments = false` on the job class (Rails 6.1 and later; check your version).
- SQL logs show bound values in development. In production keep the log level at `:info` or above so debug query logs are off.

## Serializers and JSON

- `render json: @user` renders every attribute through `as_json`. Prefer an explicit serializer, `as_json(only: [...])` or `to_json(only: [...])`.
- With ActiveModel::Serializers, Blueprinter, Alba or jbuilder, review `attributes` lines for sensitive fields. A field for the owner only should be conditional on the current user.
- Check `default_scope` and `includes` that pull records into a response which then expose nested users.
- `has_secure_password` stores a digest; never serialize the digest column either.

## Error tracking

sentry-ruby: leave `config.send_default_pii` off unless the data is needed, and use `config.before_send` to scrub events. See `trackers-analytics.md`. The Rails integration is documented to use the app's parameter filter for request data; confirm on your version.
