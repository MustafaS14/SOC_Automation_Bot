import json

import pytest

from .web_helpers import PASSWORD, login, post, stack, token  # noqa: F401


def test_login_required_everywhere(stack):
    app, _, _ = stack
    client = app.test_client()
    for path in ("/", "/incidents", "/incidents/1", "/hunt", "/enrich", "/ask", "/audit"):
        resp = client.get(path)
        assert resp.status_code == 302 and "/login" in resp.headers["Location"], path


def test_login_success_and_wrong_password(stack):
    app, _, _ = stack
    client, resp = login(app, "triage")
    assert resp.status_code == 302
    assert client.get("/").status_code == 200

    _, bad = login(app, "triage", "wrong password here")
    assert bad.status_code == 401
    assert b"Wrong username or password" in bad.data


def test_login_error_does_not_reveal_which_part_was_wrong(stack):
    app, _, _ = stack
    _, unknown = login(app, "nobody", PASSWORD)
    _, wrong = login(app, "triage", "nope nope nope nope")
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.data == wrong.data or (b"Wrong username or password" in unknown.data and b"Wrong username or password" in wrong.data)


def test_account_locks_after_repeated_failures(stack):
    app, _, _ = stack
    for _ in range(3):
        login(app, "read", "bad password here")
    _, resp = login(app, "read", PASSWORD)  # even the right password is refused while locked
    assert resp.status_code == 401


def test_post_without_csrf_token_is_rejected(stack):
    app, _, _ = stack
    client, _ = login(app, "triage")
    resp = client.post("/incidents/1/comment", data={"message": "hi"})
    assert resp.status_code == 400
    resp = client.post("/incidents/1/comment", data={"message": "hi", "csrf_token": "forged"})
    assert resp.status_code == 400


def test_login_form_needs_csrf_token(stack):
    app, _, _ = stack
    resp = app.test_client().post("/login", data={"username": "triage", "password": PASSWORD})
    assert resp.status_code == 400


def test_logout_ends_the_session(stack):
    app, _, _ = stack
    client, _ = login(app, "triage")
    assert post(client, "/logout", "/").status_code == 302
    assert client.get("/").status_code == 302


def test_disabled_user_is_signed_out_on_next_request(stack):
    app, _, users = stack
    client, _ = login(app, "triage")
    users.set_active("triage", False)
    assert client.get("/").status_code == 302


def test_tier_change_applies_to_existing_session(stack):
    app, _, users = stack
    client, _ = login(app, "triage")
    assert client.get("/incidents").status_code == 200
    users.set_tier("triage", "viewer")
    assert client.get("/incidents").status_code == 403


@pytest.mark.parametrize(
    "tier,path,expected",
    [
        ("viewer", "/", 200), ("viewer", "/ask", 200), ("viewer", "/incidents", 403),
        ("viewer", "/hunt", 403), ("viewer", "/enrich", 403), ("viewer", "/audit", 403),
        ("read", "/incidents", 200), ("read", "/hunt", 200), ("read", "/enrich", 200), ("read", "/audit", 403),
        ("triage", "/audit", 403), ("admin", "/audit", 200),
    ],
)
def test_page_access_by_tier(stack, tier, path, expected):
    app, _, _ = stack
    client, _ = login(app, tier)
    assert client.get(path).status_code == expected


def test_viewer_dashboard_shows_counts_but_no_incident_list(stack):
    app, _, _ = stack
    client, _ = login(app, "viewer")
    html = client.get("/").get_data(as_text=True)
    assert "Open incidents" in html
    assert "soc-victim" not in html and "Suspicious discovery" not in html


def test_read_tier_cannot_change_incidents(stack):
    app, backends, _ = stack
    client, _ = login(app, "read")
    for path, data in (
        ("/incidents/1/ack", {}),
        ("/incidents/1/comment", {"message": "hello"}),
        ("/incidents/1/close", {"classification": "benign", "comment": "fine", "step": "confirm"}),
    ):
        assert post(client, path, "/incidents", **data).status_code == 403, path
    inc = backends.runner.run(backends.store.get(1))
    assert inc.status == "New" and not inc.comments


def test_incident_list_and_filters(stack):
    app, _, _ = stack
    client, _ = login(app, "read")
    html = client.get("/incidents?status=open").get_data(as_text=True)
    assert "Suspicious discovery commands" in html and "Cron job anomaly" not in html
    html = client.get("/incidents?status=closed").get_data(as_text=True)
    assert "Cron job anomaly" in html
    # Junk filter values fall back to defaults instead of reaching the store.
    assert client.get("/incidents?status=%27%3BDROP&severity=x&limit=abc").status_code == 200


def test_missing_incident_is_404(stack):
    app, _, _ = stack
    client, _ = login(app, "read")
    assert client.get("/incidents/9999").status_code == 404


def test_acknowledge_comment_and_audit(stack):
    app, backends, _ = stack
    client, _ = login(app, "triage")
    assert post(client, "/incidents/1/ack", "/incidents/1").status_code == 302
    assert post(client, "/incidents/1/comment", "/incidents/1", message="Looks like recon").status_code == 302
    inc = backends.runner.run(backends.store.get(1))
    assert inc.status == "Active" and inc.assignee == "triage@web"
    assert inc.comments[-1].author == "triage@web" and inc.comments[-1].body == "Looks like recon"
    backends.audit_log.close()
    lines = [json.loads(line) for line in open(backends.settings.audit_log_path, encoding="utf-8")]
    actions = {(e["action"], e["actor"], e["channel"]) for e in lines}
    assert ("incident.ack", "triage", "web") in actions and ("incident.comment", "triage", "web") in actions


def test_comment_is_escaped_not_executed(stack):
    app, backends, _ = stack
    backends.runner.run(backends.store.add_comment(1, "splunk", "<script>alert(1)</script>"))
    client, _ = login(app, "read")
    html = client.get("/incidents/1").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_alert_link_must_be_http(stack):
    app, backends, _ = stack
    inc = backends.runner.run(backends.store.create(rule="r", severity="Low", url="javascript:alert(1)"))
    client, _ = login(app, "read")
    assert "javascript:" not in client.get(f"/incidents/{inc.id}").get_data(as_text=True)
    ok = backends.runner.run(backends.store.create(rule="r", severity="Low", url="https://splunk.lab:8000/a"))
    assert "https://splunk.lab:8000/a" in client.get(f"/incidents/{ok.id}").get_data(as_text=True)


def test_empty_comment_rejected(stack):
    app, backends, _ = stack
    client, _ = login(app, "triage")
    post(client, "/incidents/1/comment", "/incidents/1", message="   ")
    assert backends.runner.run(backends.store.get(1)).comments == []


def test_close_needs_a_second_confirming_post(stack):
    app, backends, _ = stack
    client, _ = login(app, "triage")
    data = {"classification": "false_positive", "comment": "Scheduled scan"}
    review = post(client, "/incidents/1/close", "/incidents/1", **data)
    assert review.status_code == 200 and b"Close incident #1?" in review.data
    assert backends.runner.run(backends.store.get(1)).status == "New"

    done = post(client, "/incidents/1/close", "/incidents/1", step="confirm", **data)
    assert done.status_code == 302
    inc = backends.runner.run(backends.store.get(1))
    assert inc.status == "Closed" and inc.classification == "false_positive"
    assert "Scheduled scan" in inc.comments[-1].body


def test_close_rejects_bad_classification_and_short_reason(stack):
    app, backends, _ = stack
    client, _ = login(app, "triage")
    post(client, "/incidents/1/close", "/incidents/1", classification="whatever", comment="a reason", step="confirm")
    post(client, "/incidents/1/close", "/incidents/1", classification="benign", comment="x", step="confirm")
    assert backends.runner.run(backends.store.get(1)).status == "New"


def test_closing_twice_reports_instead_of_crashing(stack):
    app, _, _ = stack
    client, _ = login(app, "triage")
    data = {"classification": "benign", "comment": "fine", "step": "confirm"}
    post(client, "/incidents/1/close", "/incidents/1", **data)
    again = post(client, "/incidents/1/close", "/incidents/1", **data)
    assert again.status_code == 302
    assert b"already closed" in client.get("/incidents/1").data


def test_enrich_form_and_incident_link(stack):
    app, backends, _ = stack
    client, _ = login(app, "read")
    resp = post(client, "/enrich", "/enrich", ip="185.220.101.4", incident="2")
    assert resp.status_code == 200 and b"Malicious" in resp.data
    assert "IP enrichment 185.220.101.4" in backends.runner.run(backends.store.get(2)).comments[-1].body


def test_enrich_button_on_incident_uses_its_source_ip(stack):
    app, _, _ = stack
    client, _ = login(app, "read")
    resp = post(client, "/incidents/2/enrich", "/incidents/2")
    assert resp.status_code == 200 and b"185.220.101.4" in resp.data


def test_enrich_rejects_junk_ip(stack):
    app, _, _ = stack
    client, _ = login(app, "read")
    resp = post(client, "/enrich", "/enrich", ip="not-an-ip; rm -rf /")
    assert resp.status_code == 302
    assert b"not a valid IPv4/IPv6" in client.get("/enrich").data


def test_enrich_private_ip_is_internal(stack):
    app, _, _ = stack
    client, _ = login(app, "read")
    assert b"Internal" in post(client, "/enrich", "/enrich", ip="192.168.56.20").data


def test_hunt_runs_template_and_validates_target(stack):
    app, _, _ = stack
    client, _ = login(app, "read")
    ok = post(client, "/hunt", "/hunt", template="host_commands", window="1h", target="soc-victim")
    assert ok.status_code == 200 and b"whoami" in ok.data
    bad = post(client, "/hunt", "/hunt", template="host_commands", window="1h", target='x" | delete')
    assert b"whoami" not in bad.data
    unknown = post(client, "/hunt", "/hunt", template="../etc", window="1h", target="")
    assert b"Unknown hunt template" in unknown.data


def test_ask_answers_at_the_users_level(stack):
    app, _, _ = stack
    client, _ = login(app, "viewer")
    resp = post(client, "/ask", "/ask", question="How many incidents are open?")
    assert resp.status_code == 200 and b"Answer" in resp.data


def test_ask_requires_a_question(stack):
    app, _, _ = stack
    client, _ = login(app, "viewer")
    assert b"Ask a question first" in post(client, "/ask", "/ask", question="   ").data


def test_audit_page_lists_entries_for_admin(stack):
    app, _, _ = stack
    client, _ = login(app, "admin")
    client.get("/incidents")
    html = client.get("/audit").get_data(as_text=True)
    assert "incident.list" in html and "auth.login" in html


def test_failed_login_is_audited_without_the_password(stack):
    app, backends, _ = stack
    login(app, "triage", "hunter2 hunter2 hunter2")
    backends.audit_log.close()
    text = open(backends.settings.audit_log_path, encoding="utf-8").read()
    assert '"outcome": "denied"' in text and "hunter2" not in text


def test_security_headers(stack):
    app, _, _ = stack
    resp = app.test_client().get("/login")
    assert "default-src 'none'" in resp.headers["Content-Security-Policy"]
    assert "script-src" not in resp.headers["Content-Security-Policy"]  # no scripts are allowed at all
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Cache-Control"] == "no-store"
    assert "inline" not in resp.get_data(as_text=True).lower() and "<script" not in resp.get_data(as_text=True)


def test_session_cookie_flags(stack):
    app, _, _ = stack
    client = app.test_client()
    page = client.get("/login")
    resp = client.post("/login", data={"username": "triage", "password": PASSWORD, "csrf_token": token(page.get_data(as_text=True))})
    cookie = resp.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie


def test_login_attempts_are_throttled_per_address(stack):
    app, _, _ = stack
    client = app.test_client()
    page = client.get("/login").get_data(as_text=True)
    codes = [client.post("/login", data={"username": "ghost", "password": "x" * 14, "csrf_token": token(page)}).status_code
             for _ in range(25)]
    assert 429 in codes and codes[0] == 401


# ---- space-UI theme: ranks, threat level, self-hosted fonts, nothing inline ----

@pytest.mark.parametrize(
    "open_by_severity,expected",
    [
        ({}, ("clear", 1)),
        ({"Informational": 2}, ("guarded", 2)),
        ({"Low": 1}, ("guarded", 2)),
        ({"Low": 1, "Medium": 1}, ("elevated", 3)),
        ({"Medium": 1, "High": 1, "Low": 4}, ("critical", 4)),
        ({"High": 0, "Medium": 0}, ("clear", 1)),  # zero counts do not raise the level
    ],
)
def test_threat_level_follows_the_worst_open_severity(open_by_severity, expected):
    from soc_web.app import threat_level

    level, steps, reason = threat_level(open_by_severity)
    assert (level, steps) == expected and reason


def test_rank_names_cover_every_tier_and_show_in_the_header(stack):
    from soc_bot.rbac import Permission
    from soc_web.app import RANKS

    assert set(RANKS) == set(Permission)
    for tier, rank in (("viewer", "Cadet"), ("read", "Scout"), ("triage", "Pilot"), ("admin", "Commander")):
        client, _ = login(stack[0], tier)
        assert rank in client.get("/").get_data(as_text=True)


def test_dashboard_shows_threat_level_and_clears_when_nothing_is_open(stack):
    app, backends, _ = stack
    client, _ = login(app, "read")
    html = client.get("/").get_data(as_text=True)
    assert "CRITICAL" in html and "High-severity incidents are open" in html  # the seeded High incident
    for incident_id in (1, 2, 3, 4):
        backends.runner.run(backends.store.close(incident_id, "benign", "test", "t"))
    html = client.get("/").get_data(as_text=True)
    assert "All clear" in html and ">CLEAR<" in html  # the heading is uppercased by CSS


def test_fonts_are_self_hosted_and_allowed_by_the_csp(stack):
    app, _, _ = stack
    client = app.test_client()
    for name in ("Orbitron.ttf", "Exo2.ttf"):
        resp = client.get(f"/static/fonts/{name}")
        assert resp.status_code == 200 and resp.data[:4] == b"\x00\x01\x00\x00"
    csp = client.get("/login").headers["Content-Security-Policy"]
    assert "font-src 'self'" in csp
    assert "http" not in csp and "script-src" not in csp  # still nothing from outside, still no scripts


def test_no_page_uses_inline_styles_or_scripts(stack):
    app, _, _ = stack
    client, _ = login(app, "admin")
    for path in ("/", "/incidents", "/incidents/2", "/hunt", "/enrich", "/ask", "/audit", "/nope"):
        html = client.get(path).get_data(as_text=True)
        assert " style=" not in html and "<script" not in html and " onclick=" not in html, path
    assert " style=" not in app.test_client().get("/login").get_data(as_text=True)


def test_ask_shows_a_plain_words_box_separate_from_the_technical_answer(stack):
    app, _, _ = stack
    client, _ = login(app, "viewer")
    html = post(client, "/ask", "/ask", question="summarize incident 1").get_data(as_text=True)
    answer_part, _, plain_part = html.partition('class="panel plain"')
    assert "In plain words" in plain_part and "monitoring system" in plain_part
    assert "Not checked" in answer_part                       # the technical answer is in its own box
    assert "In plain words:" not in answer_part               # the marker itself is not left in it


def test_ask_shows_no_plain_words_box_for_a_refusal(stack):
    app, _, _ = stack
    client, _ = login(app, "viewer")
    html = post(client, "/ask", "/ask", question="What's the weather tomorrow?").get_data(as_text=True)
    assert "I can only help with this SOC" in html and 'class="panel plain"' not in html


def test_logout_revokes_a_copied_session_cookie(stack):
    app, _, _ = stack
    client, _ = login(app, "triage")
    cookie = client.get_cookie("soc_session").value
    post(client, "/logout", "/")
    thief = app.test_client()
    thief.set_cookie("soc_session", cookie)
    assert thief.get("/").status_code == 302


def test_password_change_signs_out_existing_sessions(stack):
    app, _, users = stack
    client, _ = login(app, "triage")
    users.set_password("triage", "a brand new password")
    assert client.get("/").status_code == 302
    _, resp = login(app, "triage", "a brand new password")
    assert resp.status_code == 302


def test_logout_leaves_other_users_signed_in(stack):
    app, _, _ = stack
    a, _ = login(app, "triage")
    b, _ = login(app, "read")
    post(a, "/logout", "/")
    assert b.get("/").status_code == 200
