"""Static contract checks for the operator console (frontend/console).

The console is plain HTML/CSS/JS served under a strict Content-Security-Policy
(script-src 'self'; style-src 'self'). These checks keep the properties that policy and the
security notes in app.js rely on, and catch markup/script drift that would break a view.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

CONSOLE = Path(__file__).resolve().parents[3] / "frontend" / "console"
HTML = (CONSOLE / "index.html").read_text(encoding="utf-8")
JS = (CONSOLE / "app.js").read_text(encoding="utf-8")
CSS = (CONSOLE / "app.css").read_text(encoding="utf-8")


class _Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: list[str] = []
        self.inline_style_tags = 0
        self.inline_scripts = 0
        self.style_attrs: list[str] = []
        self.handler_attrs: list[str] = []
        self.external: list[str] = []
        self._in_script_without_src = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if "id" in a:
            self.ids.append(a["id"])
        if "style" in a:
            self.style_attrs.append(tag)
        self.handler_attrs += [k for k in a if k.startswith("on")]
        if tag == "style":
            self.inline_style_tags += 1
        if tag == "script":
            if a.get("src"):
                self.external.append(a["src"])
            else:
                self._in_script_without_src = True
        if tag == "link" and a.get("href"):
            self.external.append(a["href"])

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script_without_src = False

    def handle_data(self, data):
        if self._in_script_without_src and data.strip():
            self.inline_scripts += 1


def _collect() -> _Collector:
    c = _Collector()
    c.feed(HTML)
    return c


def test_every_element_the_script_looks_up_exists():
    ids = set(_collect().ids)
    wanted = set(re.findall(r'\$\("#([A-Za-z0-9_-]+)', JS))
    assert wanted, "expected $(\"#id\") lookups in app.js"
    missing = sorted(wanted - ids)
    assert not missing, f"app.js looks up ids that index.html does not define: {missing}"


def test_element_ids_are_unique():
    ids = _collect().ids
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    assert not dupes, f"duplicate ids: {dupes}"


def test_every_nav_entry_has_a_view():
    views = set(re.findall(r'data-view="([a-z]+)"', HTML))
    sections = set(re.findall(r'<section id="view-([a-z]+)"', HTML))
    assert views and views <= sections, f"nav entries without a view: {sorted(views - sections)}"


def test_markup_is_compatible_with_the_strict_csp():
    c = _collect()
    assert c.inline_scripts == 0, "inline <script> blocks are blocked by script-src 'self'"
    assert c.inline_style_tags == 0, "<style> blocks are blocked by style-src 'self'"
    assert not c.style_attrs, f"style attributes are blocked by style-src 'self': {c.style_attrs}"
    assert not c.handler_attrs, f"inline event handlers are blocked: {c.handler_attrs}"


def test_console_loads_nothing_from_other_origins():
    for ref in _collect().external:
        assert ref.startswith("/console/"), f"external or non-console resource: {ref}"
    assert not re.search(r"https?://", CSS), "the stylesheet must not fetch remote resources"
    assert "@import" not in CSS


def test_script_never_parses_html_from_data():
    # API values (user agents, request paths) are attacker-controlled: textContent only.
    for pattern in (r"\.innerHTML\b", r"\.outerHTML\b", r"insertAdjacentHTML", r"document\.write",
                    r"\beval\(", r"new Function\("):
        code = "\n".join(line for line in JS.splitlines() if not line.lstrip().startswith("//"))
        assert not re.search(pattern, code), f"forbidden DOM/HTML sink in app.js: {pattern}"


def test_script_never_sets_style_attributes():
    # setAttribute("style", ...) is an inline style and is refused under style-src 'self';
    # CSSOM writes (element.style.x = ...) are allowed.
    assert not re.search(r"""setAttribute\(\s*["']style["']""", JS)
    assert not re.search(r"""\{\s*style\s*:""", JS), "el(..., { style: ... }) would set a style attribute"


def test_token_is_never_put_in_a_url():
    # The access token travels only in the Authorization header / WebSocket auth message.
    assert not re.search(r"[?&](token|access_token)=", JS)
    assert "localStorage.setItem(\"hs_token\"" not in JS, "the session token belongs in sessionStorage"


def test_both_colour_schemes_define_every_token():
    root = re.search(r":root\s*\{(.*?)\n\}", CSS, re.S).group(1)
    dark = re.search(r':root\[data-theme="dark"\]\s*\{(.*?)\n\}', CSS, re.S).group(1)
    light_tokens = set(re.findall(r"(--[a-z0-9-]+)\s*:", root))
    dark_tokens = set(re.findall(r"(--[a-z0-9-]+)\s*:", dark))
    colourish = {t for t in light_tokens if re.search(
        rf"{re.escape(t)}\s*:\s*(#|rgba?\()", root)}
    missing = sorted(colourish - dark_tokens)
    assert not missing, f"colour tokens without a dark value: {missing}"


def _backend_sources() -> str:
    app = Path(__file__).resolve().parents[2] / "app"
    return "\n".join(p.read_text(encoding="utf-8") for p in app.rglob("*.py"))


def test_audit_filter_lists_every_recorded_event_type():
    """The audit filter is a fixed list, so a new audit event type must be added to it."""
    src = _backend_sources()
    recorded = set(re.findall(r'event_type="([A-Z][A-Z0-9_]+)"', src))
    recorded |= set(re.findall(r'_record\([^,()]+,\s*"([A-Z][A-Z0-9_]+)"', src))          # MFA service helper
    for a, b in re.findall(r'\w*type\s*=\s*"([A-Z][A-Z0-9_]+)"\s+if\s[^\n]+?\selse\s+"([A-Z][A-Z0-9_]+)"', src):
        recorded |= {a, b}                                                                  # chosen at runtime
    assert len(recorded) > 40, "the scan no longer finds the audit event types"
    missing = sorted(t for t in recorded if f"{t}:" not in JS)
    assert not missing, f"add these to AUDIT_TYPES in app.js: {missing}"


def test_every_chain_failure_kind_is_explained():
    src = _backend_sources()
    kinds = set(re.findall(r'\.fail\("([a-z_]+)"', src))
    assert len(kinds) >= 8
    missing = sorted(k for k in kinds if f"{k}:" not in JS)
    assert not missing, f"add these to CHAIN_FAILURES in app.js: {missing}"
