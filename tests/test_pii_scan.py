import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import pii_scan as scan  # noqa: E402

SCRIPT = Path(scan.__file__)


def project(tmp_path, files):
    for name, body in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    return tmp_path


def codes(tmp_path, files):
    project(tmp_path, files)
    return sorted(f.code for f in scan.scan_path(str(tmp_path)))


@pytest.mark.parametrize("name,line", [
    ("app/a.rb", "Rails.logger.info(params)"),
    ("app/a.rb", 'logger.info "got #{params}"'),
    ("app/a.rb", "logger.debug(request.headers.inspect)"),
    ("app/a.rb", "puts current_user.inspect"),
    ("app/a.py", "logger.info(request.POST)"),
    ("app/a.py", "print(request.data)"),
    ("app/a.py", "logging.warning('x %s', request.user)"),
    ("app/a.php", "Log::info($request->all());"),
    ("app/a.php", "Log::debug('in', request()->all());"),
    ("app/a.php", "Log::info($user->toArray());"),
    ("src/a.js", "console.log(req.body);"),
    ("src/a.ts", "logger.info({ req }, 'incoming');"),
    ("src/a.js", "logger.debug(JSON.stringify(req.headers));"),
])
def test_whole_object_logging_is_flagged(tmp_path, name, line):
    assert codes(tmp_path, {name: line + "\n"}) == ["PII-LOG-OBJECT"]


@pytest.mark.parametrize("name,line", [
    ("app/a.rb", "logger.info(params[:id])"),
    ("app/a.rb", 'logger.info("id=#{user.id}")'),
    ("app/a.py", "logger.info(request.method)"),
    ("app/a.py", "logger.info(request.POST.get('page'))"),
    ("app/a.php", "Log::info('x', ['id' => $user->id]);"),
    ("src/a.js", "console.log(req.body.id);"),
    ("src/a.js", "logger.info({ id: user.id });"),
    ("app/a.rb", "x = params"),
])
def test_safe_logging_is_not_flagged(tmp_path, name, line):
    assert codes(tmp_path, {name: line + "\n"}) == []


@pytest.mark.parametrize("name,line", [
    ("app/a.rb", 'logger.info "login #{user.api_token}"'),
    ("app/a.py", 'logger.info(f"card {card_number}")'),
    ("src/a.js", "console.log(`sent to ${user.email}`);"),
    ("src/a.js", "logger.info(req.body.email);"),
    ("app/a.php", 'Log::info("phone: {$user->phone}");'),
])
def test_sensitive_field_in_log_is_flagged(tmp_path, name, line):
    assert codes(tmp_path, {name: line + "\n"}) == ["PII-LOG-FIELD"]


@pytest.mark.parametrize("name,line", [
    ("app/a.rb", 'logger.info "Password reset email sent"'),
    ("app/a.rb", 'logger.info "token #{mask(user.api_token)}"'),
    ("app/a.rb", 'logger.info "x" # pii: ok token'),
    ("src/a.js", "logger.info('email queue drained');"),
    ("app/a.rb", 'x = "#{user.email}"'),
])
def test_sensitive_word_false_positives_are_skipped(tmp_path, name, line):
    assert codes(tmp_path, {name: line + "\n"}) == []


def test_finding_severity_and_no_source_echo(tmp_path):
    project(tmp_path, {"app/a.rb": 'logger.info "t #{user.api_token} hunter2xyz"\n'})
    finding = scan.scan_path(str(tmp_path))[0]
    assert finding.severity == "high" and finding.line == 1 and finding.path.endswith("a.rb")
    assert "hunter2xyz" not in json.dumps(finding.__dict__)


@pytest.mark.parametrize("name,line,code", [
    ("src/s.js", "Sentry.init({ dsn, sendDefaultPii: true });", "PII-TRACKER-PII"),
    ("app/s.py", "sentry_sdk.init(send_default_pii=True)", "PII-TRACKER-PII"),
    ("app/s.rb", "config.send_default_pii = true", "PII-TRACKER-PII"),
    ("app/s.php", "'send_default_pii' => true,", "PII-TRACKER-PII"),
    ("app/s.py", 'sentry_sdk.init(max_request_body_size="always")', "PII-TRACKER-BODY"),
    ("src/s.js", "Sentry.setUser({ email: user.email });", "PII-TRACKER-USER"),
    ("app/s.py", "sentry_sdk.set_user({'email': user.email})", "PII-TRACKER-USER"),
    ("app/s.rb", "Sentry.set_user(email: user.email)", "PII-TRACKER-USER"),
    ("src/s.js", "mixpanel.track('signup', { phone: user.phone });", "PII-ANALYTICS"),
    ("app/s.rb", "ahoy.track 'x', email: user.email", "PII-ANALYTICS"),
    ("src/s.js", "analytics.identify(user.id, { email: user.email });", "PII-ANALYTICS"),
])
def test_tracker_and_analytics_rules(tmp_path, name, line, code):
    assert codes(tmp_path, {name: line + "\n"}) == [code]


@pytest.mark.parametrize("name,line", [
    ("src/s.js", "Sentry.init({ sendDefaultPii: false });"),
    ("app/s.py", "sentry_sdk.init(send_default_pii=False)"),
    ("app/s.py", 'sentry_sdk.init(max_request_body_size="never")'),
    ("src/s.js", "Sentry.setUser({ id: user.id });"),
    ("src/s.js", "mixpanel.track('signup', { plan: 'pro' });"),
])
def test_tracker_safe_settings_not_flagged(tmp_path, name, line):
    assert codes(tmp_path, {name: line + "\n"}) == []


@pytest.mark.parametrize("name,line,code", [
    ("app/controllers/u.rb", "render json: @user", "PII-SERIALIZER-WHOLE"),
    ("app/controllers/u.rb", "render json: users, status: :ok", "PII-SERIALIZER-WHOLE"),
    ("src/u.js", "res.json(user);", "PII-SERIALIZER-WHOLE"),
    ("src/u.ts", "return res.send(customer);", "PII-SERIALIZER-WHOLE"),
    ("app/serializers.py", "    fields = '__all__'", "PII-SERIALIZER-ALL"),
    ("app/serializers/u.rb", "  attributes :id, :email, :phone", "PII-SERIALIZER-FIELD"),
    ("app/serializers/u.rb", "  attributes :id, :api_token", "PII-SERIALIZER-FIELD"),
    ("app/Http/Resources/UserResource.php", "'email' => $this->email,", "PII-SERIALIZER-FIELD"),
    ("src/user.serializer.ts", "  email: string;", "PII-SERIALIZER-FIELD"),
])
def test_serializer_rules(tmp_path, name, line, code):
    assert codes(tmp_path, {name: line + "\n"}) == [code]


@pytest.mark.parametrize("name,line", [
    ("app/controllers/u.rb", "render json: @user.as_json(only: [:id])"),
    ("app/controllers/u.rb", "render json: @user, serializer: UserSerializer"),
    ("app/controllers/u.rb", "render json: { id: user.id }"),
    ("app/serializers/u.rb", "  attributes :id, :name"),
    ("app/serializers/u.rb", "  # attributes :email"),
    ("app/serializers/u.rb", "  attribute :email, if: :admin?"),
    ("app/models/u.rb", "  attributes :email"),
])
def test_serializer_safe_not_flagged(tmp_path, name, line):
    assert codes(tmp_path, {name: line + "\n"}) == []


def test_rails_missing_filter_initializer(tmp_path):
    assert codes(tmp_path, {"config/application.rb": "module App; end\n"}) == ["PII-RAILS-NOFILTER"]


def test_rails_filter_initializer_present(tmp_path):
    files = {
        "config/application.rb": "module App; end\n",
        "config/initializers/filter_parameter_logging.rb":
            "Rails.application.config.filter_parameters += [:passw, :email]\n",
    }
    assert codes(tmp_path, files) == []


def test_rails_filter_cleared(tmp_path):
    files = {
        "config/application.rb": "module App; end\n",
        "config/initializers/filter_parameter_logging.rb":
            "Rails.application.config.filter_parameters.clear\n",
    }
    assert codes(tmp_path, files) == ["PII-RAILS-NOFILTER"]


def test_rails_filter_initializer_without_setting(tmp_path):
    files = {"config/application.rb": "x\n", "config/initializers/filter_parameter_logging.rb": "# todo\n"}
    assert codes(tmp_path, files) == ["PII-RAILS-NOFILTER"]


def test_django_post_access_without_sensitive_decorator(tmp_path):
    body = "def login(request):\n    pw = request.POST['card_number']\n"
    assert codes(tmp_path, {"app/views.py": body}) == ["PII-DJANGO-NOSENSITIVE"]


def test_django_post_access_with_decorator_ok(tmp_path):
    body = (
        "from django.views.decorators.debug import sensitive_post_parameters\n"
        "@sensitive_post_parameters('card_number')\n"
        "def login(request):\n    pw = request.POST['card_number']\n"
    )
    assert codes(tmp_path, {"app/views.py": body}) == []


def test_laravel_model_without_hidden(tmp_path):
    body = "class User extends Model {\n    protected $fillable = ['name', 'api_token'];\n}\n"
    assert codes(tmp_path, {"app/Models/User.php": body}) == ["PII-LARAVEL-NOHIDDEN"]


def test_laravel_model_with_hidden_ok(tmp_path):
    body = (
        "class User extends Model {\n    protected $fillable = ['name', 'api_token'];\n"
        "    protected $hidden = ['api_token'];\n}\n"
    )
    assert codes(tmp_path, {"app/Models/User.php": body}) == []


def test_pino_without_redact(tmp_path):
    assert codes(tmp_path, {"src/log.js": "const logger = pino({ level: 'info' });\n"}) == ["PII-NODE-NOREDACT"]


def test_pino_with_redact_ok(tmp_path):
    body = "const logger = pino({ redact: ['req.headers.authorization'] });\n"
    assert codes(tmp_path, {"src/log.js": body}) == []


def test_nest_entity_sensitive_column_without_exclude(tmp_path):
    body = "@Entity()\nexport class User {\n  @Column()\n  phone: string;\n}\n"
    assert codes(tmp_path, {"src/user.entity.ts": body}) == ["PII-NEST-ENTITY"]


def test_nest_entity_with_exclude_ok(tmp_path):
    body = "@Entity()\nexport class User {\n  @Exclude()\n  @Column()\n  phone: string;\n}\n"
    assert codes(tmp_path, {"src/user.entity.ts": body}) == []


DOT_ENV = "." + "env"
DB_CONFIG = "data" + "base"


def test_secret_bearing_files_are_never_read(tmp_path, monkeypatch):
    bad = "Rails.logger.info(params)\n"
    files = {
        DOT_ENV: bad, DOT_ENV + ".production": bad, "app/" + DOT_ENV + ".local": bad,
        f"config/{DB_CONFIG}.php": "<?php Log::info($request->all());\n",
        f"config/{DB_CONFIG}.rb": bad, "config/credentials.rb": bad, "config/master.key": bad,
        "config/secrets.rb": bad, "app/settings.py": "print(request.data)\n",
        "app/settings/base.py": "print(request.data)\n", "app/local_settings.py": "print(request.data)\n",
        "config/initializers/aws_credentials.rb": bad, "app/server.pem": bad, "app/id_rsa": bad,
        "app/ok.rb": "x = 1\n",
    }
    project(tmp_path, files)
    opened = []
    original = scan.read_file
    monkeypatch.setattr(scan, "read_file", lambda p: (opened.append(Path(p).name), original(p))[1])
    assert scan.scan_path(str(tmp_path)) == []
    assert opened == ["ok.rb"]


def test_only_known_config_files_are_read(tmp_path, monkeypatch):
    files = {
        "config/application.rb": "x\n",
        "config/initializers/filter_parameter_logging.rb": "config.filter_parameters += [:a]\n",
        "config/initializers/sentry.rb": "config.send_default_pii = true\n",
        "config/app.php": "<?php Log::info($request->all());\n",
    }
    project(tmp_path, files)
    results = scan.scan_path(str(tmp_path))
    assert sorted((Path(f.path).name, f.code) for f in results) == [("sentry.rb", "PII-TRACKER-PII")]


def test_tests_and_vendor_dirs_skipped_unless_included(tmp_path):
    files = {"spec/a_spec.rb": "puts params\n", "node_modules/x/a.js": "console.log(req.body)\n",
             "tests/a.py": "print(request.data)\n"}
    project(tmp_path, files)
    assert scan.scan_path(str(tmp_path)) == []
    assert len(scan.scan_path(str(tmp_path), include_tests=True)) == 2


def test_symlinks_and_large_files_skipped(tmp_path):
    project(tmp_path, {"app/big.rb": "puts params\n" + "#" * (scan.MAX_BYTES + 1)})
    outside = tmp_path.parent / "outside_pii.rb"
    outside.write_text("puts params\n")
    (tmp_path / "app" / "link.rb").symlink_to(outside)
    assert scan.scan_path(str(tmp_path)) == []


def test_single_file_target(tmp_path):
    project(tmp_path, {"app/a.rb": "puts params\n"})
    assert [f.code for f in scan.scan_path(str(tmp_path / "app" / "a.rb"))] == ["PII-LOG-OBJECT"]


def test_secret_file_given_directly_is_refused(tmp_path):
    project(tmp_path, {DOT_ENV: "puts params\n"})
    assert scan.scan_path(str(tmp_path / DOT_ENV)) == []


def run_cli(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)


def test_cli_exit_codes_and_json(tmp_path):
    project(tmp_path, {"app/a.rb": "puts params\n"})
    result = run_cli("--json", str(tmp_path))
    assert result.returncode == 1
    assert json.loads(result.stdout)[0]["code"] == "PII-LOG-OBJECT"
    project(tmp_path, {"app/a.rb": "x = 1\n"})
    assert run_cli(str(tmp_path)).returncode == 0


def test_cli_missing_path_is_usage_error(tmp_path):
    assert run_cli(str(tmp_path / "nope")).returncode == 2


def test_cli_min_severity(tmp_path):
    project(tmp_path, {"app/a.rb": 'logger.info "u #{user.email}"\n'})
    assert run_cli("--min-severity", "high", str(tmp_path)).returncode == 0
    assert run_cli("--min-severity", "medium", str(tmp_path)).returncode == 1


def test_script_has_no_network_shell_or_env_access():
    import ast
    tree = ast.parse(SCRIPT.read_text())
    banned = {"socket", "urllib", "http", "requests", "subprocess", "ssl", "ftplib", "smtplib", "httpx", "aiohttp"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not banned & {a.name.split(".")[0] for a in node.names}
        if isinstance(node, ast.ImportFrom):
            assert node.module.split(".")[0] not in banned
        if isinstance(node, ast.Attribute):
            assert node.attr not in {"environ", "getenv", "system", "popen"}


def test_hidden_directories_are_skipped(tmp_path):
    project(tmp_path, {".github/scripts/a.rb": "puts params\n"})
    assert scan.scan_path(str(tmp_path)) == []


@pytest.mark.parametrize("line", [
    "Log::info($request->only(['name']));", "Log::info($request->ip());", "Log::info($request->user()->id);",
])
def test_php_request_attribute_access_not_flagged(tmp_path, line):
    assert codes(tmp_path, {"app/a.php": line + "\n"}) == []


@pytest.mark.parametrize("line", ["console.log(req.user);", "logger.info(req.session);"])
def test_node_req_user_and_session_flagged(tmp_path, line):
    assert codes(tmp_path, {"src/a.js": line + "\n"}) == ["PII-LOG-OBJECT"]


def test_nest_inline_decorator_property_checked(tmp_path):
    body = "@Entity()\nclass U {\n  @Column() email: string;\n}\n"
    assert codes(tmp_path, {"src/u.ts": body}) == ["PII-NEST-ENTITY"]


def test_nest_exemption_does_not_leak_to_next_property(tmp_path):
    body = (
        "@Entity()\nclass U {\n  @Column({ select: false })\n  password: string;\n"
        "  @Column()\n  token: string;\n}\n"
    )
    result = scan.scan_path(str(project(tmp_path, {"src/u.ts": body})))
    assert [(f.code, f.line) for f in result] == [("PII-NEST-ENTITY", 6)]


def test_unreadable_file_is_skipped(tmp_path, monkeypatch):
    project(tmp_path, {"app/a.rb": "puts params\n", "app/b.rb": "puts params\n"})
    original = scan.read_file

    def flaky(path):
        if path.endswith("a.rb"):
            raise PermissionError(path)
        return original(path)

    monkeypatch.setattr(scan, "read_file", flaky)
    assert [Path(f.path).name for f in scan.scan_path(str(tmp_path))] == ["b.rb"]


def test_nest_inline_exemption_does_not_leak_between_inline_properties(tmp_path):
    body = "@Entity()\nclass U {\n  @Column({ select: false }) password: string;\n  @Column() email: string;\n}\n"
    result = scan.scan_path(str(project(tmp_path, {"src/u.ts": body})))
    assert [(f.code, f.line) for f in result] == [("PII-NEST-ENTITY", 4)]


def test_nest_decorator_with_nested_parens_checked(tmp_path):
    body = "@Entity()\nclass U {\n  @Column({ length: len() }) phone: string;\n}\n"
    assert codes(tmp_path, {"src/u.ts": body}) == ["PII-NEST-ENTITY"]


def test_nest_multiline_decorator_exemption(tmp_path):
    body = "@Entity()\nclass U {\n  @Column({\n    select: false,\n  })\n  token: string;\n}\n"
    assert codes(tmp_path, {"src/u.ts": body}) == []


def test_optional_chaining_on_req_user_not_flagged(tmp_path):
    assert codes(tmp_path, {"src/a.js": "console.log(req.user?.id);\n"}) == []


def test_nest_exemption_does_not_leak_without_semicolons(tmp_path):
    body = "@Entity()\nclass U {\n  @Column({ select: false })\n  password: string\n  @Column()\n  email: string\n}\n"
    result = scan.scan_path(str(project(tmp_path, {"src/u.ts": body})))
    assert [(f.code, f.line) for f in result] == [("PII-NEST-ENTITY", 6)]
