"""Heuristic static scan for personal or secret data leaking into logs, error trackers, analytics and serializers."""

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass

SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "vendor", "__pycache__",
    "tmp", "log", "storage", "dist", "build", "coverage", "settings", ".next", ".idea",
}
TEST_DIRS = {"spec", "test", "tests", "__tests__", "features", "fixtures", "e2e", "cypress"}
LANG_BY_EXT = {
    ".rb": "ruby", ".py": "python", ".php": "php",
    ".js": "node", ".jsx": "node", ".mjs": "node", ".cjs": "node", ".ts": "node", ".tsx": "node",
}
DENIED_NAME = re.compile(
    r"^\.|settings|secret|credential|database|id_rsa|\.(?:key|pem|p12|pfx|jks|keystore)$",
    re.I,
)
MAX_BYTES = 1_000_000
SUPPRESS_MARKER = "pii: ok"
SEVERITY_RANK = {"medium": 1, "high": 2}
FILTER_INITIALIZER = os.path.join("config", "initializers", "filter_parameter_logging.rb")

HIGH_WORDS = [
    "password", "passwd", "secret", "token", "api_key", "apikey", "authorization", "cookie",
    "ssn", "card_number", "cardnumber", "cvv", "cvc", "iban", "private_key", "otp",
]
MEDIUM_WORDS = ["email", "phone", "national_id", "passport", "dob", "birth_date", "date_of_birth"]


def word_regex(words):
    alts = []
    for word in words:
        lower = word.replace("_", "_?")
        camel = "".join(part.capitalize() for part in word.split("_"))
        alts.append(rf"(?<![A-Za-z])(?i:{lower})s?(?![A-Za-z])")
        alts.append(rf"(?<=[a-z0-9]){camel}s?(?![A-Za-z])")
    return re.compile("|".join(alts))


HIGH_RE = word_regex(HIGH_WORDS)
MEDIUM_RE = word_regex(MEDIUM_WORDS)

LITERAL = re.compile(r"""(?P<q>["'`])(?P<body>(?:\\.|(?!(?P=q)).)*)(?P=q)""")
INTERPOLATION = re.compile(r"#\{([^}]*)\}|\$\{([^}]*)\}|\{([^}]*)\}")
COMMENT = {
    "ruby": re.compile(r"\s#.*$"), "python": re.compile(r"\s#.*$"),
    "php": re.compile(r"\s(?:#|//).*$"), "node": re.compile(r"\s//.*$"),
}
COMMENT_START = ("#", "//", "*", "/*")
MASKED = re.compile(r"mask|redact|filtered|sanitiz|scrub|obfuscat|anonymi", re.I)

LOG_LEVELS = r"(?:trace|debug|info|notice|warn|warning|error|exception|critical|fatal|alert|emergency|log|verbose|silly|http)"
LOG_CALL = {
    "ruby": re.compile(r"\b(?:Rails\.)?logger\.(?:debug|info|warn|error|fatal|unknown|add)\b|\b(?:puts|pp|print)\b"),
    "python": re.compile(rf"\b(?:logger|logging|log)\.{LOG_LEVELS}\s*\(|\bprint\s*\("),
    "php": re.compile(
        rf"\bLog::\w+\s*\(|(?:\$\w+|\))->{LOG_LEVELS}\s*\(|"
        r"\b(?:logger|info|error_log|dd|dump|var_dump|print_r|var_export)\s*\("
    ),
    "node": re.compile(
        rf"\bconsole\.(?:log|info|warn|error|debug|dir|trace)\s*\(|(?<!Math\.)\b(?:logger|log)\.{LOG_LEVELS}\s*\("
    ),
}

AFTER_NAME = r"(?![\w\[\(:]|\.(?!inspect|to_h|to_s|to_json|as_json|to_unsafe_h|attributes|dict|copy|items|__dict__)\w)"
WHOLE_OBJECT = {
    "ruby": re.compile(
        r"(?<![\w.:])(?:@?(?:params|current_user|user|payload)|"
        r"request\.(?:params|headers|env|body|raw_post|parameters|request_parameters|query_parameters))"
        + AFTER_NAME
    ),
    "python": re.compile(
        r"(?<![\w.])(?:self\.)?(?:request\.(?:POST|GET|data|body|META|headers|COOKIES|session|user|FILES)|request)"
        + AFTER_NAME + r"|(?<![\w.])(?:user|customer)" + AFTER_NAME + r"|\blocals\(\)|\bvars\(\w+\)|\w+\.__dict__|\bmodel_to_dict\("
    ),
    "php": re.compile(
        r"\$request->(?:all|input|post|query|json|headers|cookies|server|toArray)\(\s*\)|"
        r"\brequest\(\)->(?:all|input|post|query|json|headers|cookies|server|toArray)\(\s*\)|"
        r"\$request->headers->all\(\)|\$\w*[uU]ser\w*->(?:toArray|toJson|attributesToArray|getAttributes)\(\)|"
        r"\b(?:Auth::user|auth\(\)->user)\(\)(?!->\w)|\$request(?!\s*->|\w)|\$_(?:POST|GET|REQUEST|COOKIE|SERVER)\b(?!\s*\[)"
    ),
    "node": re.compile(
        r"(?<![\w.])(?:ctx\.)?(?:req|request)\.(?:body|headers|query|cookies|params|rawHeaders|user|session)\b"
        r"(?![\w\[\(:?]|\.(?!toString|toJSON)\w)|"
        r"\{\s*(?:req|request|user|body|headers)\s*[,}]|(?<![\w.])(?:req|request|user|customer|account)(?=\s*[,)])"
    ),
}

SEND_DEFAULT_PII = re.compile(r"send_?default_?pii\W{0,4}(?:=>|=|:)\s*true", re.I)
BODY_ALWAYS = re.compile(r"max_?request_?body_?size\W{0,4}always", re.I)
SET_USER = re.compile(r"\b(?:setUser|set_user)\b")
ANALYTICS_CALL = re.compile(
    r"\b(?:analytics|mixpanel|amplitude|segment|posthog|ahoy|heap|rudderanalytics)\s*\.\s*"
    r"(?:track|identify|capture|alias|group|people\.set|setUserProperties|set_user_properties)\b"
)

ENTITY_NAMES = r"user|users|customer|customers|account|accounts|member|members|profile|profiles"
SERIALIZER_PATH = re.compile(r"serializer|blueprint|resource|presenter|transformer", re.I)
WHOLE_RECORD = {
    "ruby": re.compile(rf"render\s+json:\s*\(?@?(?:{ENTITY_NAMES}|current_user)\b(?:\.(?:to_json|as_json))?\s*(?:,|\)|$)"),
    "node": re.compile(rf"\bres\b(?:\.status\(\d+\))?\.(?:json|send)\(\s*(?:await\s+)?(?:{ENTITY_NAMES})\s*\)"),
    "php": re.compile(rf"response\(\)->json\(\s*\$(?:{ENTITY_NAMES})\s*\)"),
}
WHOLE_RECORD_EXEMPT = re.compile(r"only:|except:|serializer:|each_serializer|include:|methods:")
FIELDS_ALL = re.compile(r"""\bfields\s*=\s*['"]__all__['"]""")
FIELD_EXEMPT = re.compile(r"except|exclude|hidden|write_only|\bif\b|\bunless\b|@Exclude")

DJANGO_POST_ACCESS = re.compile(r"request\.(?:POST|data)\b")
LARAVEL_MODEL = re.compile(r"class\s+\w+\s+extends\s+\w*(?:Model|Authenticatable)\b")
LARAVEL_MASS_FIELDS = re.compile(r"\$(?:fillable|casts)\s*=\s*\[(.*?)\]", re.S)
PINO_CALL = re.compile(r"\bpino(?:Http)?\s*\(")
NEST_ENTITY = re.compile(r"@Entity\s*\(")
NEST_PROPERTY = re.compile(r"^\s*(?:@\w+\(.*?\)\s*)*(?:(?:public|private|protected|readonly)\s+)*\w+[!?]?\s*:")
NEST_EXEMPT = re.compile(r"@Exclude|select:\s*false")

FILTER_SETTING = re.compile(r"^(?!\s*#).*filter_parameters", re.M)
FILTER_CLEARED = re.compile(r"filter_parameters\s*(?:\.clear\b|=\s*\[\s*\])")

MESSAGES = {
    "PII-LOG-OBJECT": "logs a whole request, params or user object; log named non-sensitive fields instead",
    "PII-LOG-FIELD": "logs a field that looks personal or secret; drop it, mask it or log an id",
    "PII-TRACKER-PII": "error tracker is set to send default PII (cookies, headers, user ip); review before enabling",
    "PII-TRACKER-BODY": "error tracker is set to always attach request bodies; scrub or turn it off",
    "PII-TRACKER-USER": "error tracker user context carries personal data; send an opaque id",
    "PII-ANALYTICS": "analytics call carries personal data; send an opaque id and non-identifying traits",
    "PII-SERIALIZER-WHOLE": "returns a whole record without a field list; use a serializer or an explicit allow list",
    "PII-SERIALIZER-ALL": "serializer exposes every model field; list fields explicitly",
    "PII-SERIALIZER-FIELD": "serializer exposes a personal or secret field; confirm every consumer needs it",
    "PII-RAILS-NOFILTER": "no usable filter_parameters setting found in the standard initializer; filter secrets and personal params",
    "PII-DJANGO-NOSENSITIVE": "reads sensitive POST data in a file with no sensitive_post_parameters decorator",
    "PII-LARAVEL-NOHIDDEN": "model mass-assigns secret-looking attributes but declares no hidden or visible list",
    "PII-NODE-NOREDACT": "pino logger created without a redact option; redact auth headers and personal fields",
    "PII-NEST-ENTITY": "entity property looks personal or secret with no @Exclude or select: false; check response serialization",
}


@dataclass
class Finding:
    code: str
    severity: str
    path: str
    line: int
    message: str


def make_finding(code, severity, path, line):
    return Finding(code, severity, path, line, MESSAGES[code])


def read_file(path):
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def literal_view(line, match):
    body = match.group("body")
    start = match.start()
    if start > 0 and line[start - 1] == "[" and re.fullmatch(r"\w+", body):
        return f" {body} "
    parts = [next(g for g in m.groups() if g is not None) for m in INTERPOLATION.finditer(body)]
    return " " + " ".join(parts) + " "


def code_view(line, lang):
    return COMMENT[lang].sub("", LITERAL.sub(lambda m: literal_view(line, m), line))


def severity_of_words(text):
    if HIGH_RE.search(text):
        return "high"
    if MEDIUM_RE.search(text):
        return "medium"
    return None


def scan_log_line(view, lang):
    call = LOG_CALL[lang].search(view)
    if not call or MASKED.search(view):
        return []
    rest = view[call.end():]
    hits = []
    if WHOLE_OBJECT[lang].search(rest):
        hits.append(("PII-LOG-OBJECT", "high"))
    severity = severity_of_words(rest)
    if severity:
        hits.append(("PII-LOG-FIELD", severity))
    return hits


def scan_tracker_line(line, view):
    hits = []
    if SEND_DEFAULT_PII.search(line):
        hits.append(("PII-TRACKER-PII", "high"))
    if BODY_ALWAYS.search(line):
        hits.append(("PII-TRACKER-BODY", "high"))
    if SET_USER.search(view) and severity_of_words(view):
        hits.append(("PII-TRACKER-USER", "medium"))
    if ANALYTICS_CALL.search(view) and severity_of_words(view):
        hits.append(("PII-ANALYTICS", "medium"))
    return hits


def scan_serializer_line(line, lang, is_serializer_file):
    hits = []
    pattern = WHOLE_RECORD.get(lang)
    if pattern and pattern.search(line) and not WHOLE_RECORD_EXEMPT.search(line):
        hits.append(("PII-SERIALIZER-WHOLE", "medium"))
    if lang == "python" and FIELDS_ALL.search(line):
        hits.append(("PII-SERIALIZER-ALL", "medium"))
    if is_serializer_file and not FIELD_EXEMPT.search(line):
        severity = severity_of_words(line)
        if severity:
            hits.append(("PII-SERIALIZER-FIELD", severity))
    return hits


def scan_line_rules(lines, lang, path, rel):
    findings = []
    is_serializer_file = bool(SERIALIZER_PATH.search(rel))
    for number, line in enumerate(lines, 1):
        if SUPPRESS_MARKER in line or line.lstrip().startswith(COMMENT_START):
            continue
        view = code_view(line, lang)
        hits = scan_log_line(view, lang) + scan_tracker_line(line, view)
        hits += scan_serializer_line(line, lang, is_serializer_file)
        findings += [make_finding(code, severity, path, number) for code, severity in hits]
    return findings


def first_line(lines, predicate):
    return next((n for n, line in enumerate(lines, 1) if predicate(line)), None)


def scan_file_rules(text, lines, lang, path):
    findings = []
    if lang == "python" and "sensitive_post_parameters" not in text:
        number = first_line(lines, lambda l: DJANGO_POST_ACCESS.search(l) and HIGH_RE.search(l))
        if number:
            findings.append(make_finding("PII-DJANGO-NOSENSITIVE", "medium", path, number))
    if lang == "php" and LARAVEL_MODEL.search(text) and not re.search(r"\$(?:hidden|visible)\b|makeHidden", text):
        mass = LARAVEL_MASS_FIELDS.search(text)
        if mass and HIGH_RE.search(mass.group(1)):
            findings.append(make_finding("PII-LARAVEL-NOHIDDEN", "high", path, text[:mass.start()].count("\n") + 1))
    if lang == "node" and "redact" not in text:
        number = first_line(lines, lambda l: PINO_CALL.search(l))
        if number:
            findings.append(make_finding("PII-NODE-NOREDACT", "medium", path, number))
    if lang == "node" and NEST_ENTITY.search(text):
        findings += scan_nest_entity(lines, path)
    return findings


def ends_property(line):
    if re.search(r"\bclass\b|;\s*$|^\s*}?\s*$", line):
        return True
    text = line.strip()
    return bool(NEST_PROPERTY.match(line)) and not text.startswith("@") and not text.endswith((",", "{"))


def decorators_of(lines, number):
    block = [lines[number - 1]]
    index = number - 2
    while index >= 0 and not ends_property(lines[index]):
        block.append(lines[index])
        index -= 1
    return "\n".join(block)


def scan_nest_entity(lines, path):
    findings = []
    for number, line in enumerate(lines, 1):
        severity = severity_of_words(line) if NEST_PROPERTY.match(line) else None
        if severity and not NEST_EXEMPT.search(decorators_of(lines, number)):
            findings.append(make_finding("PII-NEST-ENTITY", severity, path, number))
    return findings


def scan_text(text, lang, path, rel=None):
    lines = text.splitlines()
    return scan_line_rules(lines, lang, path, rel or path) + scan_file_rules(text, lines, lang, path)


def is_denied(name):
    return bool(DENIED_NAME.search(name))


def scan_rails_filter(root):
    if not os.path.isfile(os.path.join(root, "config", "application.rb")):
        return []
    initializer = os.path.join(root, FILTER_INITIALIZER)
    if not os.path.isfile(initializer):
        return [make_finding("PII-RAILS-NOFILTER", "medium", os.path.join(root, "config", "application.rb"), 1)]
    text = read_file(initializer)
    if FILTER_CLEARED.search(text) or not FILTER_SETTING.search(text):
        return [make_finding("PII-RAILS-NOFILTER", "medium", initializer, 1)]
    return []


def walk_files(root, include_tests):
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        skip = SKIP_DIRS if include_tests else SKIP_DIRS | TEST_DIRS
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in skip and not d.startswith(".") and not os.path.exists(os.path.join(dirpath, d, "pyvenv.cfg"))
        )
        in_config = os.path.basename(dirpath) == "config"
        if in_config:
            dirnames[:] = [d for d in dirnames if d == "initializers"]
        for name in sorted(filenames):
            if not in_config:
                yield os.path.join(dirpath, name)


def scannable(path):
    ext = os.path.splitext(path)[1].lower()
    if ext not in LANG_BY_EXT or is_denied(os.path.basename(path)) or os.path.islink(path):
        return False
    return os.path.getsize(path) <= MAX_BYTES


def scan_path(target, include_tests=False):
    findings = []
    base = target if os.path.isdir(target) else os.path.dirname(target)
    if os.path.isfile(target):
        paths = [target]
    else:
        paths = walk_files(target, include_tests)
        findings += scan_rails_filter(target)
    for path in paths:
        if not scannable(path):
            continue
        try:
            text = read_file(path)
        except OSError:
            continue
        findings += scan_text(text, LANG_BY_EXT[os.path.splitext(path)[1].lower()], path, os.path.relpath(path, base))
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description="Heuristic scan for personal or secret data leaking into logs and responses.")
    parser.add_argument("paths", nargs="*", default=["."])
    parser.add_argument("--json", action="store_true", help="print findings as JSON")
    parser.add_argument("--min-severity", choices=sorted(SEVERITY_RANK), default="medium")
    parser.add_argument("--include-tests", action="store_true", help="also scan spec, test and fixture folders")
    args = parser.parse_args(argv)
    missing = [p for p in args.paths if not os.path.exists(p)]
    if missing:
        print(f"path not found: {', '.join(missing)}", file=sys.stderr)
        return 2
    threshold = SEVERITY_RANK[args.min_severity]
    findings = [
        f for path in args.paths for f in scan_path(path, args.include_tests)
        if SEVERITY_RANK[f.severity] >= threshold
    ]
    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        for f in findings:
            print(f"{f.path}:{f.line}: [{f.severity}] {f.code} {f.message}")
        print(f"{len(findings)} finding(s). Heuristic: confirm each one.", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
