import pytest

from soc_bot.models import Incident, IpReport


def report(**kwargs):
    return IpReport(ip="1.1.1.1", is_public=True, **kwargs)


def test_internal_ip_is_never_judged():
    assert IpReport(ip="10.0.0.1", is_public=False, abuse_score=100).verdict == "Internal"


@pytest.mark.parametrize(
    "kwargs, expected",
    [
        ({"abuse_score": 75}, "Malicious"),
        ({"abuse_score": 74}, "Suspicious"),
        ({"vt_malicious": 5}, "Malicious"),
        ({"vt_malicious": 4}, "Suspicious"),
        ({"vt_malicious": 3}, "Suspicious"),
        ({"vt_malicious": 2}, "Clean"),
        ({"abuse_score": 25}, "Suspicious"),
        ({"abuse_score": 24}, "Clean"),
        ({"abuse_score": 0, "vt_malicious": 1}, "Clean"),  # 8.8.8.8: one engine of 54, AbuseIPDB 0
        ({"abuse_score": 0, "vt_malicious": 0, "vt_suspicious": 5}, "Suspicious"),
        ({"abuse_score": 0, "vt_malicious": 0, "vt_suspicious": 4}, "Clean"),
        ({}, "Unknown"),
    ],
)
def test_verdict_thresholds(kwargs, expected):
    assert report(**kwargs).verdict == expected


def test_failed_lookup_is_incomplete_not_clean():
    partial = report(abuse_score=0, errors=["VirusTotal: ReadTimeout"])
    assert partial.verdict == "Incomplete"
    partial.errors.clear()
    assert partial.verdict == "Clean"


def test_both_lookups_failing_is_incomplete():
    assert report(errors=["AbuseIPDB: ReadTimeout", "VirusTotal: ReadTimeout"]).verdict == "Incomplete"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"abuse_score": 0, "errors": ["VirusTotal: ReadTimeout"]},
        {"abuse_score": 10, "errors": ["VirusTotal: ReadTimeout"]},
        {"vt_malicious": 0, "vt_suspicious": 1, "errors": ["AbuseIPDB: ReadTimeout"]},
        {"vt_malicious": 0, "vt_harmless": 70, "errors": ["AbuseIPDB: HTTPStatusError"]},
    ],
)
def test_one_source_failed_and_the_other_found_nothing_bad_is_incomplete(kwargs):
    assert report(**kwargs).verdict == "Incomplete"


def test_unknown_only_when_there_are_no_errors_and_no_data():
    assert report().verdict == "Unknown"
    assert report(errors=["x"]).verdict == "Incomplete"
    assert report(abuse_score=0).verdict == "Clean"


def test_real_findings_win_over_a_failed_lookup():
    assert report(abuse_score=90, errors=["VirusTotal: ReadTimeout"]).verdict == "Malicious"
    assert report(vt_malicious=3, errors=["AbuseIPDB: ReadTimeout"]).verdict == "Suspicious"
    # One engine alone is noise, so with the other lookup down the answer is not a finding yet.
    assert report(vt_malicious=1, errors=["AbuseIPDB: ReadTimeout"]).verdict == "Incomplete"


def test_incident_from_row_parses_timestamps_and_nulls():
    row = {
        "id": 3, "rule": "r", "severity": "High", "status": "New", "host": None, "src_ip": None,
        "assignee": None, "description": None, "url": None, "classification": None,
        "created": "2026-10-17T10:00:00+00:00", "updated": "not a date",
    }
    incident = Incident.from_row(row)
    assert incident.created.year == 2026 and incident.updated is None
    assert incident.description == "" and incident.comments == []


def test_parse_techniques_accepts_text_and_lists_and_drops_junk():
    from soc_bot.models import parse_techniques

    assert parse_techniques("T1033, t1057;T1033 nonsense T12") == ["T1033", "T1057"]
    assert parse_techniques(["T1036.004", "<b>", 3]) == ["T1036.004"]
    assert parse_techniques(None) == [] and parse_techniques(7) == []


def test_incident_from_a_row_without_the_techniques_column_has_no_techniques():
    from soc_bot.models import Incident

    row = {"id": 1, "rule": "r", "severity": "Low", "status": "New", "host": None, "src_ip": None, "assignee": None,
           "description": "", "url": None, "classification": None, "created": None, "updated": None}
    assert Incident.from_row(row).techniques == []
    assert Incident.from_row({**row, "techniques": "T1033,T1057"}).techniques == ["T1033", "T1057"]
