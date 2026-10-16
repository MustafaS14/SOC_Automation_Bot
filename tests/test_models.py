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
        ({"abuse_score": 25}, "Suspicious"),
        ({"abuse_score": 24}, "Clean"),
        ({"abuse_score": 0, "vt_malicious": 1}, "Suspicious"),
        ({"abuse_score": 0, "vt_malicious": 0, "vt_suspicious": 2}, "Suspicious"),
        ({"abuse_score": 0, "vt_malicious": 0, "vt_suspicious": 1}, "Clean"),
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


def test_real_findings_win_over_a_failed_lookup():
    assert report(abuse_score=90, errors=["VirusTotal: ReadTimeout"]).verdict == "Malicious"
    assert report(vt_malicious=1, errors=["AbuseIPDB: ReadTimeout"]).verdict == "Suspicious"


def test_incident_from_row_parses_timestamps_and_nulls():
    row = {
        "id": 3, "rule": "r", "severity": "High", "status": "New", "host": None, "src_ip": None,
        "assignee": None, "description": None, "url": None, "classification": None,
        "created": "2026-10-17T10:00:00+00:00", "updated": "not a date",
    }
    incident = Incident.from_row(row)
    assert incident.created.year == 2026 and incident.updated is None
    assert incident.description == "" and incident.comments == []
