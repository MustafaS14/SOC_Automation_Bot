"""The look must stay readable: WCAG contrast for the colour pairs the stylesheet really uses (text 4.5:1, focus
outline and form-field borders 3:1)."""

import re
from pathlib import Path

import pytest

CSS = (Path(__file__).resolve().parents[1] / "soc_web" / "static" / "style.css").read_text(encoding="utf8")
COLORS = {name: tuple(int(h[i:i + 2], 16) for i in (1, 3, 5))
          for name, h in re.findall(r"--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})", CSS)}
COLORS["refusal"] = (0x2A, 0x1D, 0x12)  # background of the Ask refusal panel (.panel.refusal)
COLORS["denied-row"] = tuple(round(f * .12 + b * .88) for f, b in zip(COLORS["red"], COLORS["panel"]))  # tr.denied


def _luminance(c):
    f = lambda x: x / 255 / 12.92 if x / 255 <= .03928 else ((x / 255 + .055) / 1.055) ** 2.4  # noqa: E731
    r, g, b = map(f, c)
    return .2126 * r + .7152 * g + .0722 * b


def ratio(fg, bg):
    hi, lo = sorted((_luminance(COLORS[fg]), _luminance(COLORS[bg])), reverse=True)
    return (hi + .05) / (lo + .05)


TEXT = [("text", "panel"), ("muted", "panel"), ("muted", "deep"), ("muted", "readout"), ("teal", "panel"),
        ("teal", "deep"), ("cream", "panel"), ("red", "panel"), ("orange", "panel"), ("red", "deep"),
        ("cream", "refusal"), ("orange", "refusal"), ("muted", "refusal"), ("text", "denied-row"),
        ("muted", "denied-row"), ("ink", "teal"), ("ink", "cream")]
NON_TEXT = [("cream", "panel"), ("cream", "bg"), ("field", "panel"), ("field", "deep"), ("red", "deep"),
            ("teal", "deep"), ("muted", "deep")]


@pytest.mark.parametrize("fg, bg", TEXT)
def test_text_contrast(fg, bg):
    assert ratio(fg, bg) >= 4.5, f"{fg} on {bg} is {ratio(fg, bg):.2f}:1"


@pytest.mark.parametrize("fg, bg", NON_TEXT)
def test_focus_outline_field_borders_and_status_dots(fg, bg):
    assert ratio(fg, bg) >= 3.0, f"{fg} against {bg} is {ratio(fg, bg):.2f}:1"


def test_placeholders_are_not_left_at_the_browser_default():
    assert re.search(r"::placeholder\s*\{[^}]*color:\s*var\(--muted\)", CSS)


def test_form_fields_use_the_visible_border():
    assert "border: 3px solid var(--field)" in CSS


def test_the_refusal_panel_colour_in_the_test_matches_the_stylesheet():
    assert ".panel.refusal { background: #2a1d12;" in CSS


# ---- rendered pages: labels and "not by colour alone" ----------------------------------------------------------

from html.parser import HTMLParser  # noqa: E402

from .web_helpers import login, post, stack  # noqa: E402, F401


class _Fields(HTMLParser):
    def __init__(self):
        super().__init__()
        self.labels, self.fields = set(), []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "label" and a.get("for"):
            self.labels.add(a["for"])
        if tag in ("input", "select", "textarea") and a.get("type") != "hidden":
            self.fields.append(a)


PAGES = ["/", "/incidents", "/incidents/1", "/hunt", "/enrich", "/ask", "/audit"]


def test_every_form_field_has_a_label(stack):
    app, _, _ = stack
    client, _ = login(app, "admin")
    for path in PAGES:
        parser = _Fields()
        parser.feed(client.get(path).get_data(as_text=True))
        for field in parser.fields:
            named = field.get("aria-label") or (field.get("id") in parser.labels)
            if field.get("type") == "submit":
                continue
            assert named, f"{path}: unlabeled field {field}"
    parser = _Fields()
    parser.feed(app.test_client().get("/login").get_data(as_text=True))
    assert all(f.get("id") in parser.labels or f.get("aria-label") for f in parser.fields)


def test_severity_is_always_written_out_not_only_coloured(stack):
    app, _, _ = stack
    client, _ = login(app, "read")
    html = client.get("/incidents?status=all").get_data(as_text=True)
    for badge in re.findall(r'class="badge sev-(\w+)">([^<]*)<', html):
        assert badge[0] == badge[1]  # the badge's colour class and its visible text name the same severity
    assert html.count('class="badge sev-') >= 3
    assert "★" in html  # stars add a second, non-colour cue


def test_status_dots_and_denied_rows_carry_text(stack):
    app, _, _ = stack
    html = login(app, "read")[0].get("/").get_data(as_text=True)
    assert re.search(r'class="dot st-\w+" aria-hidden="true"></i>(reachable|unreachable|not configured|checking)', html)
    assert "<b>Splunk</b>" in html
