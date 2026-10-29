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
