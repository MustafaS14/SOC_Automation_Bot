import pytest

from soc_web.answers import Facts, Para, Rows, Table, parse_answer, pretty

from .web_helpers import login, post, stack  # noqa: F401

INCIDENT = (
    "incident #1: rule=Suspicious discovery commands on soc-victim; severity=High; status=New; classification=n/a; "
    "created=2026-10-29 18:57:10 UTC; updated=2026-10-29 19:02:18 UTC; comments=3\n"
    "Confidence: low (mock assistant, no real model).\n"
    "Not checked: everything else."
)


def test_incident_line_becomes_labelled_facts_then_an_assessment():
    facts, rows = parse_answer(INCIDENT).blocks
    assert isinstance(facts, Facts) and facts.title == "Incident #1"
    assert [k for k, _ in facts.pairs] == ["rule", "severity", "status", "classification", "created", "updated", "comments"]
    assert dict(facts.pairs)["created"] == "2026-10-29 18:57:10 UTC"  # a value with spaces and colons stays whole
    assert isinstance(rows, Rows) and [r.label for r in rows.items] == ["Confidence", "Not checked"]
    assert rows.items[0].level == "low" and rows.items[0].value == "(mock assistant, no real model)."


def test_description_joins_the_incident_facts_not_the_assessment():
    text = INCIDENT.replace("\nConfidence", "\ndescription: Unusual binary under /tmp\nConfidence")
    facts, rows = parse_answer(text).blocks
    assert facts.pairs[-1] == ("description", "Unusual binary under /tmp")
    assert [r.label for r in rows.items] == ["Confidence", "Not checked"]


def test_counts_line_uses_label_colon_form():
    (facts,) = parse_answer("open incidents: 4; by status: Closed: 1, New: 4; open by severity: High: 1, Low: 1").blocks
    assert [pretty(k) for k, _ in facts.pairs] == ["Open incidents", "By status", "Open by severity"]
    assert dict(facts.pairs)["by status"] == "Closed: 1, New: 4"


def test_several_lines_with_the_same_fields_become_a_table():
    text = ("#2 rule=SSH brute force; severity=Medium; status=New; host=soc-victim; created=t2\n"
            "#1 rule=Discovery; severity=High; status=New; host=soc-victim; created=t1")
    (table,) = parse_answer(text).blocks
    assert isinstance(table, Table)
    assert table.columns == ["#", "Rule", "Severity", "Status", "Host", "Created"]
    assert table.rows[0][:3] == ["#2", "SSH brute force", "Medium"] and len(table.rows) == 2


def test_hunt_rows_become_a_table_even_when_a_value_contains_semicolons():
    text = ("_time=t1; host=soc-victim; _raw=type=EXECVE a0=\"whoami\"; then more text\n"
            "_time=t2; host=soc-victim; _raw=type=EXECVE a0=\"id\"")
    (table,) = parse_answer(text).blocks
    assert table.columns == ["Time", "Host", "Event"]
    assert table.rows[0][2] == 'type=EXECVE a0="whoami"; then more text'


@pytest.mark.parametrize(
    "prose",
    [
        "I can't tell from the available data.",
        "Looks like routine scanning; check the source address next.",   # one semicolon, not key/value
        "Note: this is only a guess; verify it.",                         # one label, not a record
        "The rule fired at 18:57, status is New, severity High.",
    ],
)
def test_prose_stays_prose(prose):
    (block,) = parse_answer(prose).blocks
    assert isinstance(block, Para) and block.text == prose


def test_real_style_answer_mixes_paragraphs_and_assessment():
    text = "Probably routine.\nEvidence: incident 3, one command.\nConfidence: medium, one source only.\nNot checked: other hosts."
    kinds = [type(b).__name__ for b in parse_answer(text).blocks]
    assert kinds == ["Para", "Rows"]
    rows = parse_answer(text).blocks[1].items
    assert [r.label for r in rows] == ["Evidence", "Confidence", "Not checked"] and rows[1].level == "medium"


def test_empty_and_blank_input():
    assert parse_answer("").blocks == [] and parse_answer("\n  \n").blocks == []


# ---- on the page ----

def test_ask_page_lays_the_incident_out_as_labelled_rows(stack):
    app, _, _ = stack
    client, _ = login(app, "read")
    html = post(client, "/ask", "/ask", question="show me the details of incident 1").get_data(as_text=True)
    assert '<dl class="facts">' in html and "<dt>Severity</dt>" in html and "sev-High" in html
    assert 'class="badge conf-low"' in html and "<dt>Not checked</dt>" in html
    assert "severity=High;" not in html and "status=New;" not in html     # the raw run-on line is gone
    assert "<dd><span class=\"muted\">none</span></dd>" in html            # n/a reads as "none"


def test_ask_page_shows_a_table_for_hunt_results(stack):
    app, _, _ = stack
    client, _ = login(app, "read")
    html = post(client, "/ask", "/ask", question="what commands ran on soc-victim in the last hour?").get_data(as_text=True)
    assert "<th>Time</th>" in html and "<th>Event</th>" in html and "whoami" in html


def test_hostile_text_in_an_answer_is_escaped(stack):
    from soc_web.answers import parse_answer as parse

    for block in parse("rule=<img src=x onerror=alert(1)>; severity=High").blocks:
        assert isinstance(block, Facts)
    app, backends, _ = stack
    backends.runner.run(backends.store.create(rule="<script>alert(1)</script>", severity="High", host="soc-victim"))
    client, _ = login(app, "read")
    html = post(client, "/ask", "/ask", question="show me the details of incident 6").get_data(as_text=True)
    # never a live tag; the assistant already escaped it once, so the page shows it as harmless text
    assert "<script>alert(1)</script>" not in html and "lt;script" in html
