import ast
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
LONG_OPAQUE_VALUE = re.compile(r"\b[A-Za-z0-9+=]{32,}\b")
SCANNER = ROOT / "scripts" / "pii_scan.py"
ALLOWED_IMPORTS = {"argparse", "json", "os", "re", "sys", "dataclasses"}
ALLOWED_ATTRS = {"sys": {"exit", "stderr"}, "os": {"path", "walk"}}
ALLOWED_PATH_ATTRS = {"basename", "dirname", "exists", "getsize", "isdir", "isfile", "islink", "join", "relpath", "splitext"}


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
    assert MANIFEST["repository"].endswith("/" + MANIFEST["name"])
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


def test_no_opaque_secret_like_values_in_shipped_text():
    for path in TEXT_FILES:
        assert not LONG_OPAQUE_VALUE.search(path.read_text()), path.name


ALLOWED_FROM_IMPORTS = {"dataclasses": {"asdict", "dataclass", "field"}}


def test_scanner_imports_only_allowed_stdlib_modules():
    imported = set()
    for node in ast.walk(ast.parse(SCANNER.read_text())):
        if isinstance(node, ast.Import):
            assert all(a.asname is None for a in node.names)
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0 and node.module in ALLOWED_FROM_IMPORTS, node.module
            assert {a.name for a in node.names} <= ALLOWED_FROM_IMPORTS[node.module]
            imported.add(node.module)
    assert imported <= ALLOWED_IMPORTS, imported - ALLOWED_IMPORTS


def test_scanner_uses_only_allowed_module_attributes():
    for node in ast.walk(ast.parse(SCANNER.read_text())):
        if not isinstance(node, ast.Attribute):
            continue
        if isinstance(node.value, ast.Name) and node.value.id in ALLOWED_ATTRS:
            assert node.attr in ALLOWED_ATTRS[node.value.id], node.attr
        inner = node.value
        if isinstance(inner, ast.Attribute) and isinstance(inner.value, ast.Name):
            if (inner.value.id, inner.attr) == ("os", "path"):
                assert node.attr in ALLOWED_PATH_ATTRS, node.attr


def test_policy_patterns_catch_known_bad_examples():
    assert DOLLAR_CREDENTIAL.search("$" + "userPass" + "wordName")
    assert DOLLAR_CREDENTIAL.search("${" + "tok" + "enValue}")
    assert DOLLAR_BRACE.search("x ${VAR}")
    assert LONG_OPAQUE_VALUE.search("a" * 40)
    assert not DOLLAR_CREDENTIAL.search("$request->all()")


def test_scanner_has_no_dynamic_escape_hatches():
    tree = ast.parse(SCANNER.read_text())
    bases = {id(n.value) for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            assert node.id not in {"__import__", "getattr", "eval", "exec", "compile", "globals", "vars"}, node.id
            if node.id in ("os", "sys") and isinstance(node.ctx, ast.Load):
                assert id(node) in bases, node.id
        if isinstance(node, ast.Attribute):
            assert not node.attr.startswith("_"), node.attr
