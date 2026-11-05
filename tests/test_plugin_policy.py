import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())
SKILL_DIR = ROOT / "skills" / "guard-pii-logs"
COMMAND = ROOT / "commands" / "guard-pii-logs.md"
SKIP_PARTS = {".pytest_cache", "__pycache__", ".git", "tests"}


def shipped(*suffixes):
    return [
        p for p in ROOT.rglob("*")
        if p.is_file() and p.suffix in suffixes and not SKIP_PARTS & set(p.relative_to(ROOT).parts)
    ]


DOCS = shipped(".md")
TEXT_FILES = shipped(".md", ".json", ".svg", ".py")

CREDENTIAL_WORDS = r"(?:password|passwd|secret|token|api_?key|credential|private_?key|auth)"
DOLLAR_CREDENTIAL = re.compile(rf"\$\{{?\w*{CREDENTIAL_WORDS}", re.I)
DOLLAR_BRACE = re.compile(r"\$\{")
UPPER_CREDENTIAL = re.compile(r"\b[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|CREDENTIAL)S?[A-Z0-9_]*\b")
ENV_ACCESS = re.compile(r"process\.env|\bENV\s*[\[.]|os\.environ|getenv|\benv\s*\(", re.I)
SECRET_FILE_MENTION = re.compile(r"\.env\b|database\.yml|credentials\.yml|master\.key|\.pem\b|~/\.claude|DATABASE_URL")


def frontmatter(path):
    return path.read_text().split("---")[1]


def test_plugin_ships_no_command_hooks():
    hooks_file = ROOT / "hooks" / "hooks.json"
    if hooks_file.exists():
        config = json.loads(hooks_file.read_text())
        hooks = [h for groups in config["hooks"].values() for group in groups for h in group["hooks"]]
        assert all(h["type"] == "prompt" for h in hooks)


def test_no_preapproved_shell_access():
    for path in list((ROOT / "commands").glob("*.md")) + list((ROOT / "agents").glob("*.md")):
        front = frontmatter(path)
        assert "Bash" not in front, path.name
        tools = re.search(r"(?:allowed-tools|tools):\s*\[?([^\]\n]*)", front).group(1)
        assert {t.strip() for t in tools.split(",")} <= {"Read", "Glob", "Grep"}, path.name


def test_command_receives_arguments_and_forbids_reading_secrets():
    text = COMMAND.read_text()
    assert "$ARGUMENTS" in text
    assert "argument-hint:" in frontmatter(COMMAND)
    assert "Never open environment files, database config, credential files" in text


def test_manifest_has_required_fields():
    for key in ("name", "description", "version", "author", "homepage", "repository", "license", "keywords", "icon"):
        assert MANIFEST.get(key), key
    assert MANIFEST["name"] == "pii-log-guard"
    assert MANIFEST["repository"] == "https://github.com/a-abdellatif98/pii-log-guard"
    assert (ROOT / MANIFEST["icon"]).is_file()


def test_manifest_version_matches_skill():
    skill = (SKILL_DIR / "SKILL.md").read_text()
    assert f"version: {MANIFEST['version']}" in skill
    assert "name: guard-pii-logs" in skill


def test_skill_references_exist():
    skill = (SKILL_DIR / "SKILL.md").read_text()
    names = set(re.findall(r"references/([\w-]+\.md)", skill + COMMAND.read_text()))
    assert names
    for name in names:
        assert (SKILL_DIR / "references" / name).is_file(), name


def test_no_root_claude_md():
    assert not (ROOT / "CLAUDE.md").exists()


def test_docs_have_no_em_or_en_dashes():
    for path in DOCS:
        text = path.read_text()
        assert "—" not in text and "–" not in text, path.name


def test_no_dollar_identifiers_that_look_like_credential_reads():
    for path in TEXT_FILES:
        assert not DOLLAR_CREDENTIAL.search(path.read_text()), path.name


def test_docs_have_no_dollar_brace_interpolation():
    for path in DOCS + [p for p in TEXT_FILES if p.suffix == ".json"]:
        assert not DOLLAR_BRACE.search(path.read_text()), path.name


def test_no_env_var_style_names():
    for path in TEXT_FILES:
        assert not UPPER_CREDENTIAL.search(path.read_text()), path.name


def test_no_environment_access_in_docs_or_scripts():
    for path in TEXT_FILES:
        assert not ENV_ACCESS.search(path.read_text()), path.name


def test_no_secret_file_names_in_shipped_text():
    for path in TEXT_FILES:
        assert not SECRET_FILE_MENTION.search(path.read_text()), path.name


def test_policy_patterns_catch_known_bad_examples():
    assert DOLLAR_CREDENTIAL.search("$authPasswordName")
    assert DOLLAR_CREDENTIAL.search("${API_TOKEN}")
    assert DOLLAR_BRACE.search("x ${VAR}")
    assert UPPER_CREDENTIAL.search("STRIPE_API_KEY")
    assert ENV_ACCESS.search("process.env.X")
    assert not DOLLAR_CREDENTIAL.search("$request->all()")
