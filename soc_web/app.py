"""The Flask app: routes, and the permission check in front of each one.

Every action calls the same store, hunt templates, enrichment client and assistant the Discord bot uses, and writes
the same audit entries (with channel "web"). Data from alerts and from Splunk is untrusted text; Jinja escapes it.
"""

from __future__ import annotations

import logging
import re
import threading
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from soc_bot import hunts
from soc_bot.ai import split_plain_words
from soc_bot.ai.assistant import MAX_QUESTION_CHARS
from soc_bot.ai.backends import CHAT_MODELS
from soc_bot.ai.prompt import DENIED_REPLY, OFF_TOPIC_REPLY
from soc_bot.ai.tools import LEVEL_LABELS
from soc_bot.audit import entry_channel, entry_denied, search
from soc_bot.clients import APIError, NotConfiguredError, NotFoundError
from soc_bot.rbac import Permission
from soc_bot.store import CLASSIFICATIONS, SEVERITIES
from soc_bot.store.incidents import ORDERS
from soc_bot.validators import ValidationError, parse_incident_ref, parse_ip

from . import pagecontext
from .answers import pretty
from .config import WebSettings
from .conversations import MAX_MESSAGES, Chat, ChatBusy, ChatError, ConversationStore
from .memory import ConversationMemory
from .remote import READ_ONLY
from .runtime import Backends
from .security import Throttle, add_headers, check_csrf, csrf_token
from .status import StatusProbe
from .users import UserStore

log = logging.getLogger("soc_web")

STATUSES = ("open", "new", "active", "closed", "all")
CLOSE_LABELS = {"true_positive": "True positive", "false_positive": "False positive", "benign": "Benign"}
MAX_HUNT_ROWS = 100
AUDIT_PAGE = 50
ORDER_LABELS = {"newest": "Newest first", "oldest": "Oldest first", "updated": "Recently updated",
                "severity": "Most severe first"}
AUDIT_CHANNELS = ("web", "discord", "cli")
AUDIT_OUTCOMES = ("success", "denied", "error", "failure")
_BASE_KEYS = {"ts", "actor", "actor_id", "action", "target", "outcome", "channel", "ip"}
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
HANDLED = (ValueError, APIError, NotConfiguredError, TimeoutError)

# Space-crew names for the tiers. Only the label changes; what each tier may do does not.
RANKS = {
    Permission.VIEWER: "Cadet", Permission.READ: "Scout", Permission.TRIAGE: "Pilot",
    Permission.RESPONSE: "Guardian", Permission.ADMIN: "Commander",
}
# Difficulty stars per severity, for the incident list.
STARS = {"High": 4, "Medium": 3, "Low": 2, "Informational": 1}


def threat_level(open_by_severity: dict[str, int]) -> tuple[str, int, str]:
    """(level, bar segments lit out of 4, one-line reason), from the worst severity that is still open."""
    for level, steps, severities, reason in (
        ("critical", 4, ("High",), "High-severity incidents are open"),
        ("elevated", 3, ("Medium",), "Medium-severity incidents are open"),
        ("guarded", 2, ("Low", "Informational"), "Only low or informational incidents are open"),
    ):
        if any(open_by_severity.get(s, 0) for s in severities):
            return level, steps, reason
    return "clear", 1, "Nothing is open"


def host_name(host: str) -> str:
    """A Host header without its port, lowercased: 'Example.com:8000' -> 'example.com', '[::1]:8000' -> '::1'."""
    host = host.strip().lower()
    if host.startswith("["):
        return host[1:].split("]", 1)[0]
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def build_timeline(inc: Any, acks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Everything that happened to an incident, oldest first: the alert, each comment (told apart by who or what wrote
    it), and acknowledgements, which the store does not keep and so come from the audit log."""
    events: list[dict[str, Any]] = [
        {"when": inc.created, "kind": "alert", "label": "Alert raised", "who": "", "text": ""}
    ]
    for c in inc.comments:
        if c.author == "triage-assistant":
            kind, label = "ai", "AI triage note"
        elif c.body.startswith("Closed as "):
            kind, label = "closed", "Closed"
        elif c.body.startswith("IP enrichment "):
            kind, label = "enrich", "IP enrichment"
        else:
            kind, label = "comment", "Comment"
        events.append({"when": c.created, "kind": kind, "label": label, "who": c.author, "text": c.body})
    for a in acks:
        try:
            when = datetime.fromisoformat(str(a.get("ts")))
        except ValueError:
            continue
        events.append({"when": when, "kind": "ack", "label": "Acknowledged", "who": str(a.get("actor", "")), "text": ""})
    events.sort(key=lambda e: e["when"] or datetime.min.replace(tzinfo=timezone.utc))
    return events


def refusal_kind(text: str, denied: bool) -> str | None:
    """"clearance" or "off_topic" when the assistant declined to answer, else None."""
    stripped = text.strip()
    if stripped.startswith(OFF_TOPIC_REPLY):
        return "off_topic"
    if stripped.startswith(DENIED_REPLY) or (denied and len(stripped) < 120):
        return "clearance"
    return None


def audit_row(e: dict[str, Any]) -> dict[str, Any]:
    """One audit entry prepared for display: its channel, the incident it concerns, and the details worth reading."""
    target = str(e.get("target", ""))
    incident = None
    if str(e.get("action", "")).startswith("incident.") and re.fullmatch(r"#\d+", target):
        incident = int(target[1:])
    elif isinstance(e.get("incident"), int):
        incident = e["incident"]
    return {
        "ts": str(e.get("ts", ""))[:19].replace("T", " "), "actor": e.get("actor", ""), "action": e.get("action", ""),
        "target": target, "outcome": e.get("outcome", ""), "channel": entry_channel(e), "ip": e.get("ip", ""),
        "denied": entry_denied(e), "incident": incident,
        "details": [(k, str(v)[:160]) for k, v in e.items() if k not in _BASE_KEYS and v not in (None, "")],
        "is_ai": e.get("action") == "ai.ask",
    }


def audit_query(args: Any) -> tuple[dict[str, str], bool, int]:
    """The audit page's filters, the denied-only switch and the page number, from a query string. Anything that is not
    a known value is ignored, so the same function serves the page and the chat widget's view of it."""
    filters = {
        "actor": args.get("actor", "").strip()[:64],
        "action": args.get("action", "").strip()[:64],
        "outcome": args.get("outcome", "") if args.get("outcome", "") in AUDIT_OUTCOMES else "",
        "channel": args.get("channel", "") if args.get("channel", "") in AUDIT_CHANNELS else "",
        "since": args.get("since", "") if _DATE.match(args.get("since", "")) else "",
        "until": args.get("until", "") if _DATE.match(args.get("until", "")) else "",
    }
    try:
        page = max(1, min(int(args.get("page", "1")), 10_000))
    except ValueError:
        page = 1
    return filters, args.get("denied") == "1", page


# The lowest tier that may open each page the chat widget can read. A user below it gets no page context at all.
CONTEXT_TIERS = {
    "dashboard": Permission.VIEWER, "incidents": Permission.READ, "incident": Permission.READ,
    "hunt": Permission.READ, "enrich_page": Permission.READ, "enrich_ip": Permission.READ,
    "audit_view": Permission.ADMIN,
}
PAGE_NAMES = {"enrich_page": "enrich page", "enrich_ip": "enrich page", "hunt": "hunt page"}


def chat_dict(chat: Chat) -> dict[str, Any]:
    return {"id": chat.id, "title": chat.title, "updated": chat.updated, "archived": chat.archived}


def create_app(web: WebSettings, backends: Backends, users: UserStore) -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=web.secret_key,
        SESSION_COOKIE_NAME="__Host-soc" if web.secure_cookies else "soc_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=web.secure_cookies,
        PERMANENT_SESSION_LIFETIME=timedelta(hours=web.session_hours),
        MAX_CONTENT_LENGTH=32 * 1024,
    )
    app.config["WEB"] = web
    if web.trusted_proxies:
        n = web.trusted_proxies
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=n, x_proto=n, x_host=n)  # type: ignore[method-assign]
    add_headers(app)
    store, runner = backends.store, backends.runner
    # Incidents read from soc-siem through the bot's API: the console can look but not change anything.
    read_only = bool(getattr(store, "remote", False))
    login_throttle = Throttle(limit=20, period=300)
    probe = StatusProbe(backends)
    memory = ConversationMemory()
    chats = ConversationStore(users)
    recent_results = pagecontext.RecentResults()
    asking: set[int] = set()  # users with a question being answered right now: one at a time, whichever tab or page
    asking_lock = threading.Lock()
    # The Sonnet/Haiku switch only means something with the real assistant; the mock ignores the choice.
    models_on = CHAT_MODELS if backends.settings.ai_backend == "claude_code" else None

    def chosen_model(value: Any) -> str:
        """The model asked for, if it is one of the allowed two and the real assistant is on; otherwise "" (default)."""
        return value if models_on and isinstance(value, str) and value in CHAT_MODELS else ""

    avatar = "bot-avatar.png" if (Path(app.static_folder or "") / "bot-avatar.png").is_file() else None

    # ---- helpers ------------------------------------------------------------------------------------------

    def call(coro: Any, timeout: float = 60.0) -> Any:
        return runner.run(coro, timeout)

    def record(actor: str, actor_id: int, action: str, target: str, outcome: str, **details: Any) -> None:
        entry = backends.audit_log.record(
            actor=actor, actor_id=actor_id, action=action, target=target, outcome=outcome,
            channel="web", ip=request.remote_addr,
            **{k: v for k, v in details.items() if v is not None},
        )
        if backends.hec:
            runner.spawn(backends.hec.send(entry))

    def audit(action: str, target: str, outcome: str = "success", **details: Any) -> None:
        record(g.user.username, g.user.id, action, target, outcome, **details)

    def explain(exc: Exception) -> str:
        """A message safe to show the user. A missing incident becomes a 404 page."""
        if isinstance(exc, NotFoundError):
            abort(404)
        if isinstance(exc, APIError):
            if exc.status == 409:
                return exc.message
            if exc.status in (401, 403):
                return f"{exc.service} rejected the console's credentials."
            return f"{exc.service} returned {exc.status}: {exc.message[:300]}"
        if isinstance(exc, TimeoutError):
            return "The request timed out. Try again."
        return str(exc)

    def author() -> str:
        return f"{g.user.username}@web"

    def needs(level: Permission):
        def decorate(view):
            @wraps(view)
            def wrapper(*args, **kwargs):
                if g.user is None:
                    return redirect(url_for("login"))
                if g.user.tier < level:
                    audit("web.access", request.path, "denied", needed=level.name)
                    abort(403)
                return view(*args, **kwargs)

            return wrapper

        return decorate

    # ---- request hooks ------------------------------------------------------------------------------------

    @app.before_request
    def load_user() -> None:
        g.user = None
        if web.allowed_hosts and host_name(request.host) not in web.allowed_hosts:
            log.warning("Refused a request with Host %r", request.host[:100])
            abort(400, "This address is not one the console answers to.")
        uid = session.get("uid")
        if uid is not None:
            # Read from the database on every request, so a disabled account or a changed tier applies at once.
            user = users.get(uid)
            if user and user.active and session.get("sv") == user.session_version:
                g.user = user
            else:
                session.clear()
        if request.method == "POST":
            check_csrf()

    # Globals, not context variables, so imported macros can use them too.
    app.jinja_env.globals.update(csrf_token=csrf_token, stars=STARS, pretty=pretty)

    @app.context_processor
    def inject() -> dict[str, Any]:
        return {"user": g.get("user"), "P": Permission, "mock": backends.settings.mock_mode,
                "sysstatus": probe.snapshot() if g.get("user") else None,
                "level_label": LEVEL_LABELS, "ranks": RANKS, "avatar": avatar,
                "chat_on": backends.assistant is not None, "chat_models": models_on, "read_only": read_only}

    @app.template_filter("when")
    def when(dt: Any) -> str:
        return dt.strftime("%Y-%m-%d %H:%M UTC") if dt else "n/a"

    @app.template_filter("safe_url")
    def safe_url(value: str | None) -> str | None:
        """Only http(s) links are rendered as links; an alert cannot smuggle in a javascript: URL."""
        if value and urlsplit(value).scheme in ("http", "https"):
            return value
        return None

    @app.errorhandler(HTTPException)
    def http_error(exc: HTTPException):
        message = {
            403: "Your account does not have access to this page.",
            404: "That page or incident does not exist.",
            429: "Too many attempts. Wait a few minutes and try again.",
        }.get(exc.code or 0, exc.description)
        return render_template("error.html", code=exc.code, message=message), exc.code or 500

    @app.errorhandler(APIError)
    def upstream(exc: APIError):
        """soc-siem (or another service) failed on a page that reads from it: say so plainly instead of a 500."""
        log.warning("%s failed on %s: %s", exc.service, request.path, exc.status)
        return render_template("error.html", code=502,
                               message=f"{exc.message} The console is up, but that data is not available right now."), 502

    @app.errorhandler(Exception)
    def unexpected(exc: Exception):
        log.exception("Unhandled error on %s", request.path)
        return render_template("error.html", code=500, message="Unexpected error. Check the console logs."), 500

    # ---- sign in and out ----------------------------------------------------------------------------------

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            if not login_throttle.allow(request.remote_addr or "?"):
                abort(429)
            username = request.form.get("username", "")
            user = users.authenticate(username, request.form.get("password", ""))
            if user is None:
                record("-", 0, "auth.login", username.strip().lower()[:64], "denied")
                flash("Wrong username or password, or the account is locked or disabled.", "error")
                return render_template("login.html"), 401
            session.clear()  # a fresh session on every login, so an old cookie cannot be reused
            session["uid"] = user.id
            session["sv"] = user.session_version
            session.permanent = True
            record(user.username, user.id, "auth.login", user.username, "success")
            return redirect(url_for("dashboard"))
        if g.user:
            return redirect(url_for("dashboard"))
        return render_template("login.html")

    @app.post("/logout")
    def logout():
        if g.user:
            audit("auth.logout", g.user.username)
            users.revoke_sessions(g.user.id)  # a copied cookie dies with the logout, not at its expiry
            memory.clear(g.user.id)
            recent_results.clear(g.user.id)
        session.clear()
        return redirect(url_for("login"))

    # ---- dashboard and incidents --------------------------------------------------------------------------

    @app.get("/")
    @needs(Permission.VIEWER)
    def dashboard():
        counts = call(store.counts())
        recent = call(store.list("open", None, 8)) if g.user.tier >= Permission.READ else []
        open_total = sum(n for status, n in counts["status"].items() if status != "Closed")
        level, steps, reason = threat_level(counts["open_by_severity"])
        return render_template("dashboard.html", counts=counts, open_total=open_total, recent=recent,
                               severities=SEVERITIES, threat=level, threat_steps=steps, threat_reason=reason)

    @app.get("/incidents")
    @needs(Permission.READ)
    def incidents():
        status = request.args.get("status", "open")
        status = status if status in STATUSES else "open"
        severity = request.args.get("severity") or None
        severity = severity if severity in SEVERITIES else None
        try:
            limit = max(1, min(int(request.args.get("limit", "25")), 50))
        except ValueError:
            limit = 25
        order = request.args.get("order", "newest")
        order = order if order in ORDERS else "newest"
        rows = call(store.list(status, severity, limit, order))
        audit("incident.list", status, severity=severity, count=len(rows), order=order)
        return render_template("incidents.html", incidents=rows, status=status, severity=severity, limit=limit,
                               order=order, orders=ORDER_LABELS, statuses=STATUSES, severities=SEVERITIES,
                               filtered=(status, severity) != ("open", None))

    @app.get("/incidents/<int:incident_id>")
    @needs(Permission.READ)
    def incident(incident_id: int):
        try:
            inc = call(store.get(incident_id))
        except NotFoundError:
            abort(404)
        audit("incident.show", f"#{inc.id}")
        acks, _ = search(backends.settings.audit_log_path, action="incident.ack", target=f"#{inc.id}",
                         outcome="success", limit=20)
        return render_template("incident.html", incident=inc, classes=CLOSE_LABELS,
                               timeline=build_timeline(inc, acks))

    def back(incident_id: int):
        return redirect(url_for("incident", incident_id=incident_id))

    def refuse_write(incident_id: int):
        """Remote mode: the POST is refused before anything is sent, with a message and no change."""
        flash(READ_ONLY, "error")
        audit("incident.write", f"#{incident_id}", "denied", reason="read-only")
        return back(incident_id), 405

    @app.post("/incidents/<int:incident_id>/ack")
    @needs(Permission.TRIAGE)
    def acknowledge(incident_id: int):
        if read_only:
            return refuse_write(incident_id)
        try:
            call(store.acknowledge(incident_id, author()))
            audit("incident.ack", f"#{incident_id}")
            flash(f"Incident #{incident_id} acknowledged.", "ok")
        except HANDLED as exc:
            flash(explain(exc), "error")
        return back(incident_id)

    @app.post("/incidents/<int:incident_id>/comment")
    @needs(Permission.TRIAGE)
    def comment(incident_id: int):
        if read_only:
            return refuse_write(incident_id)
        body = request.form.get("message", "").strip()
        if not 1 <= len(body) <= 1000:
            flash("A comment is 1 to 1000 characters.", "error")
            return back(incident_id)
        try:
            call(store.add_comment(incident_id, author(), body))
            audit("incident.comment", f"#{incident_id}", message=body)
            flash("Comment added.", "ok")
        except HANDLED as exc:
            flash(explain(exc), "error")
        return back(incident_id)

    @app.post("/incidents/<int:incident_id>/close")
    @needs(Permission.TRIAGE)
    def close_incident(incident_id: int):
        if read_only:
            return refuse_write(incident_id)
        classification = request.form.get("classification", "")
        why = request.form.get("comment", "").strip()
        if classification not in CLASSIFICATIONS:
            flash("Choose a classification.", "error")
            return back(incident_id)
        if not 3 <= len(why) <= 1000:
            flash("Say why you are closing it: 3 to 1000 characters.", "error")
            return back(incident_id)
        try:
            inc = call(store.get(incident_id))
            if inc.status == "Closed":
                flash(f"Incident #{incident_id} is already closed.", "error")
                return back(incident_id)
            if request.form.get("step") != "confirm":
                # Closing is the one change that cannot be undone, so it takes a second, explicit click.
                return render_template("confirm_close.html", incident=inc, classification=classification,
                                       label=CLOSE_LABELS[classification], why=why)
            call(store.close(incident_id, classification, why, author()))
            audit("incident.close", f"#{incident_id}", classification=CLOSE_LABELS[classification], comment=why)
            flash(f"Incident #{incident_id} closed as {CLOSE_LABELS[classification].lower()}.", "ok")
        except HANDLED as exc:
            flash(explain(exc), "error")
        return back(incident_id)

    # ---- enrich, hunt, ask --------------------------------------------------------------------------------

    def enrich_response(ip_text: str, incident_id: int | None):
        try:
            ip = parse_ip(ip_text)
            inc = call(store.get(incident_id)) if incident_id else None
            report = call(backends.enrichment.enrich_ip(str(ip)))
            if inc and not read_only:  # the note on the incident is a write, which remote mode does not do
                score = report.abuse_score if report.abuse_score is not None else "n/a"
                vt = report.vt_malicious if report.vt_malicious is not None else "n/a"
                call(store.add_comment(
                    inc.id, author(),
                    f"IP enrichment {report.ip}: verdict {report.verdict}, AbuseIPDB {score}/100, VirusTotal {vt} malicious",
                ))
            audit("enrich.ip", report.ip, verdict=report.verdict, incident=inc.id if inc else None)
            recent_results.put(g.user.id, g.user.tier, "enrich", pagecontext.enrichment(report))
            return render_template("enrich.html", report=report, incident_id=inc.id if inc else None)
        except HANDLED as exc:
            flash(explain(exc), "error")
            return redirect(url_for("enrich_page") if not incident_id else url_for("incident", incident_id=incident_id))

    @app.get("/enrich")
    @needs(Permission.READ)
    def enrich_page():
        return render_template("enrich.html", report=None, incident_id=None)

    @app.post("/enrich")
    @needs(Permission.READ)
    def enrich_ip():
        ref = request.form.get("incident", "").strip()
        try:
            incident_id = parse_incident_ref(ref) if ref else None
        except ValidationError as exc:
            flash(str(exc), "error")
            return redirect(url_for("enrich_page"))
        return enrich_response(request.form.get("ip", ""), incident_id)

    @app.post("/incidents/<int:incident_id>/enrich")
    @needs(Permission.READ)
    def enrich_incident(incident_id: int):
        try:
            inc = call(store.get(incident_id))
        except NotFoundError:
            abort(404)
        if not inc.src_ip:
            flash("This incident has no source IP.", "error")
            return back(incident_id)
        return enrich_response(inc.src_ip, inc.id)

    @app.route("/hunt", methods=["GET", "POST"])
    @needs(Permission.READ)
    def hunt():
        ctx: dict[str, Any] = {"templates": hunts.HUNTS, "windows": hunts.WINDOWS, "rows": None, "columns": [],
                               "form": {"template": "", "window": "1h", "target": ""}}
        if request.method == "POST":
            form = {k: request.form.get(k, "").strip() for k in ("template", "window", "target")}
            ctx["form"] = form
            try:
                spl, earliest = hunts.build(form["template"], form["window"], form["target"] or None)
                if backends.splunk is None:
                    raise NotConfiguredError("Splunk is not configured (SPLUNK_URL / SPLUNK_TOKEN).")
                rows = call(backends.splunk.search(spl, earliest=earliest), timeout=120)
                audit("hunt.run", form["template"], window=form["window"], hunt_target=form["target"] or None,
                      rows=len(rows))
                columns = [c for c in dict.fromkeys(k for row in rows for k in row) if not c.startswith("_") or c in ("_time", "_raw")]
                columns.sort(key=lambda c: (c != "_time", c == "_raw"))
                ctx.update(rows=rows[:MAX_HUNT_ROWS], columns=columns, total=len(rows))
                recent_results.put(g.user.id, g.user.tier, "hunt",
                                   pagecontext.hunt(form, columns, rows[:MAX_HUNT_ROWS], len(rows)))
            except HANDLED as exc:
                flash(explain(exc), "error")
        return render_template("hunt.html", **ctx)

    def ask_and_record(question: str, chat_id: int | None, *, page: pagecontext.PageContext | None,
                       via: str, history: list | None = None, model: str = "") -> tuple[Chat, Any, list]:
        """One question, asked as the signed-in user and kept in their conversation (a new one when `chat_id` is None).
        Returns the conversation, the assistant's answer and the history it was given. Raises HANDLED errors."""
        tier, uid = g.user.tier, g.user.id
        chat = chats.get(uid, tier, chat_id) if chat_id else None
        if chat_id and chat is None:
            raise ChatError("That conversation does not exist.")
        if chat and len(chats.messages(uid, tier, chat.id)) + 2 > MAX_MESSAGES:
            raise ChatError("This conversation is full. Start a new one.")
        if history is None:
            history = chats.history(uid, tier, chat.id) if chat else memory.history(uid, tier)
        # The same checks the assistant makes, done first, so a question it would refuse is never stored.
        plain = " ".join(question.split())
        if not plain:
            raise ValidationError("Ask a question first.")
        if len(plain) > MAX_QUESTION_CHARS:
            raise ValidationError(f"Keep the question under {MAX_QUESTION_CHARS} characters.")
        # One question at a time per user, across tabs and pages: a double click or a quick reload cannot start a
        # second call to the assistant (or the relay) while the first is still running. This check comes before
        # anything is stored or counted against the hourly limit.
        with asking_lock:
            if uid in asking:
                raise ChatBusy("Your previous question is still being answered. Wait for it to finish.")
            asking.add(uid)
        try:
            # The question is saved before the (possibly slow) answer is fetched. If the user opens another page
            # while it runs, the answer still lands in the conversation and the chat can pick it up again.
            if chat is None:
                chat = chats.create(uid, tier, question)
                audit("chat.new", f"#{chat.id}", via=via)
            chats.add(uid, tier, chat.id, "user", question, page=page.label if page else None)
            try:
                answer = call(
                    backends.assistant.ask(question, tier, uid, history=history,
                                           page=(page.label, page.text) if page else None, model=model),
                    timeout=backends.settings.ai_timeout + 30,
                )
            except Exception:
                # Stored so the chat stops waiting. Nothing asks again: only a person pressing Send does.
                chats.add(uid, tier, chat.id, "assistant", "The assistant did not answer. Try again.")
                raise
        finally:
            with asking_lock:
                asking.discard(uid)
        audit("ai.ask", LEVEL_LABELS[tier], answer.outcome, tools=",".join(answer.tools_used) or None,
              denied=True if answer.denied else None, calls=answer.calls, followup=len(history) or None,
              question=question[:200], page=page.label if page else None, conversation=chat.id, via=via,
              model=model or None)
        # Only answers backed by a lookup are remembered: a follow-up explains the data, and an explanation (or an
        # "ask something first" reply) is not data to explain again.
        lookup_backed = (answer.outcome == "answered" and answer.tools_used and not answer.denied
                         and not refusal_kind(answer.text, False))
        chats.add(uid, tier, chat.id, "assistant", answer.text, tools=",".join(answer.tools_used) if lookup_backed else "")
        if lookup_backed:
            memory.add(uid, tier, question, split_plain_words(answer.text)[0], ",".join(answer.tools_used))
        return chat, answer, history

    # ---- chat widget --------------------------------------------------------------------------------------

    def page_context(raw_path: str) -> pagecontext.PageContext | None:
        """What the user's current page shows, built here from the same data and for the same tier that may open it.
        The browser names the page (a path and query string); it never supplies any page text."""
        parts = urlsplit(str(raw_path)[:400])
        try:
            endpoint, values = app.url_map.bind("localhost").match(parts.path, method="GET")
        except HTTPException:
            return None
        needed = CONTEXT_TIERS.get(endpoint)
        if needed is None or g.user.tier < needed:
            return None
        query = {k: v[0] for k, v in parse_qs(parts.query[:400]).items() if v}
        tier = g.user.tier
        try:
            if endpoint == "dashboard":
                counts = call(store.counts())
                open_total = sum(n for s, n in counts["status"].items() if s != "Closed")
                recent = call(store.list("open", None, 8)) if tier >= Permission.READ else []
                return pagecontext.dashboard(counts, open_total, threat_level(counts["open_by_severity"])[0], recent)
            if endpoint == "incidents":
                status = query.get("status", "open")
                status = status if status in STATUSES else "open"
                severity = query.get("severity") if query.get("severity") in SEVERITIES else None
                order = query.get("order", "newest")
                order = order if order in ORDERS else "newest"
                try:
                    limit = max(1, min(int(query.get("limit", "25")), 50))
                except ValueError:
                    limit = 25
                return pagecontext.incident_list(call(store.list(status, severity, limit, order)), status, severity, order)
            if endpoint == "incident":
                inc = call(store.get(values["incident_id"]))
                acks, _ = search(backends.settings.audit_log_path, action="incident.ack", target=f"#{inc.id}",
                                 outcome="success", limit=20)
                return pagecontext.incident(inc, build_timeline(inc, acks))
            if endpoint == "hunt":
                return recent_results.get(g.user.id, tier, "hunt") or pagecontext.only_name(PAGE_NAMES[endpoint])
            if endpoint in ("enrich_page", "enrich_ip"):
                return recent_results.get(g.user.id, tier, "enrich") or pagecontext.only_name(PAGE_NAMES[endpoint])
            if endpoint == "audit_view":
                filters, denied_only, page = audit_query(query)
                found, total = search(backends.settings.audit_log_path, denied_only=denied_only,
                                      offset=(page - 1) * AUDIT_PAGE, limit=AUDIT_PAGE, **filters)
                shown = {k: v for k, v in {**filters, "denied": "1" if denied_only else ""}.items() if v}
                return pagecontext.audit_rows([audit_row(e) for e in found], total, shown)
        except NotFoundError:
            return None
        except HANDLED:
            log.warning("Could not build the chat context for %s", endpoint)
            return None
        return pagecontext.only_name(PAGE_NAMES.get(endpoint, endpoint))

    def json_error(message: str, code: int = 400):
        return jsonify(error=message), code

    def chat_body() -> dict[str, Any]:
        body = request.get_json(silent=True)
        return body if isinstance(body, dict) else {}

    def chat_id_from(value: Any) -> int | None:
        return value if isinstance(value, int) and not isinstance(value, bool) and 0 < value < 10**9 else None

    @app.get("/chat/conversations")
    @needs(Permission.VIEWER)
    def chat_list():
        archived = request.args.get("archived") == "1"
        waiting = chats.pending_ids(g.user.id, g.user.tier, backends.settings.ai_timeout + 60)
        return jsonify(enabled=backends.assistant is not None,
                       conversations=[{**chat_dict(c), "pending": c.id in waiting}
                                      for c in chats.list(g.user.id, g.user.tier, archived=archived)])

    @app.get("/chat/conversations/<int:chat_id>")
    @needs(Permission.VIEWER)
    def chat_messages(chat_id: int):
        chat = chats.get(g.user.id, g.user.tier, chat_id)
        if chat is None:
            return json_error("That conversation does not exist.", 404)
        messages = []
        stored = chats.messages(g.user.id, g.user.tier, chat_id)
        for m in stored:
            item: dict[str, Any] = {"role": m.role, "page": m.page}
            if m.role == "assistant":
                item["text"], item["plain"] = split_plain_words(m.text)
                item["refusal"] = refusal_kind(m.text, False)
            else:
                item["text"] = m.text
            messages.append(item)
        # An answer is "pending" while the last thing said is the user's own question and it is recent enough that the
        # assistant may still be working on it (a reply is also stored when the assistant fails, so this ends).
        pending = bool(stored) and stored[-1].role == "user" and (
            datetime.now(timezone.utc) - datetime.fromisoformat(stored[-1].created)
        ).total_seconds() < backends.settings.ai_timeout + 60
        return jsonify(conversation=chat_dict(chat), messages=messages, pending=pending)

    @app.get("/chat/context")
    @needs(Permission.VIEWER)
    def chat_context():
        """Only the name of what the widget would attach, for the chip. No model call and no page text is returned."""
        ctx = page_context(request.args.get("path", ""))
        return jsonify(label=ctx.label if ctx else None)

    @app.post("/chat/conversations/<int:chat_id>/rename")
    @needs(Permission.VIEWER)
    def chat_rename(chat_id: int):
        try:
            chats.rename(g.user.id, g.user.tier, chat_id, str(chat_body().get("title", "")))
        except ChatError as exc:
            return json_error(str(exc), 404 if "exist" in str(exc) else 400)
        audit("chat.rename", f"#{chat_id}")
        return jsonify(conversation=chat_dict(chats.get(g.user.id, g.user.tier, chat_id)))

    @app.post("/chat/conversations/<int:chat_id>/archive")
    @needs(Permission.VIEWER)
    def chat_archive(chat_id: int):
        archived = chat_body().get("archived", True) is not False
        try:
            chats.set_archived(g.user.id, g.user.tier, chat_id, archived)
        except ChatError as exc:
            return json_error(str(exc), 404)
        audit("chat.archive" if archived else "chat.unarchive", f"#{chat_id}")
        return jsonify(conversation=chat_dict(chats.get(g.user.id, g.user.tier, chat_id)))

    @app.post("/chat/ask")
    @needs(Permission.VIEWER)
    def chat_ask():
        if backends.assistant is None:
            return json_error("The AI assistant is not enabled (AI_BACKEND).", 503)
        body = chat_body()
        question = str(body.get("question", "")).strip()
        page = page_context(str(body.get("path", ""))) if body.get("use_page") is True else None
        try:
            chat, answer, _ = ask_and_record(question, chat_id_from(body.get("conversation")), page=page, via="widget",
                                             model=chosen_model(body.get("model")))
        except ChatBusy as exc:
            return json_error(str(exc), 429)
        except ChatError as exc:
            return json_error(str(exc), 404 if "exist" in str(exc) else 400)
        except HANDLED as exc:
            return json_error(explain(exc), 400)
        technical, plain = split_plain_words(answer.text)
        return jsonify(conversation=chat_dict(chat), page=page.label if page else None,
                       answer={"text": technical, "plain": plain, "outcome": answer.outcome,
                               "refusal": refusal_kind(answer.text, answer.denied)})

    # ---- audit log ----------------------------------------------------------------------------------------

    @app.get("/audit")
    @needs(Permission.ADMIN)
    def audit_view():
        filters, denied_only, page = audit_query(request.args)
        found, total = search(backends.settings.audit_log_path, denied_only=denied_only,
                              offset=(page - 1) * AUDIT_PAGE, limit=AUDIT_PAGE, **filters)
        rows = [audit_row(e) for e in found]
        shown = {k: v for k, v in {**filters, "denied": "1" if denied_only else ""}.items() if v}
        audit("audit.view", "web", count=len(rows), page=page, **{f"filter_{k}": v for k, v in shown.items()})
        return render_template(
            "audit.html", rows=rows, total=total, page=page, pages=max(1, -(-total // AUDIT_PAGE)), shown=shown,
            filters=filters, denied_only=denied_only, channels=AUDIT_CHANNELS, outcomes=AUDIT_OUTCOMES,
            forwarding=backends.hec is not None,
        )

    return app
