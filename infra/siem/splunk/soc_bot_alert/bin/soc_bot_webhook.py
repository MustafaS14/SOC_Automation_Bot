#!/usr/bin/env python3
"""Splunk alert action: POST the first result row to the SOC Bot with the secret header.

A card used to be lost when the bot was down at the moment an alert fired, because Splunk runs an alert action once
and never retries it. This script now retries a temporary failure a few times, and if the bot stays unreachable it
keeps the alert in a small on-disk spool (local/spool). It is sent again the next time any alert fires here, and also
every two minutes by a scripted input (bin/soc_bot_resend.py, which calls this script with --flush), so a card is late by
minutes on a quiet lab instead of waiting for the next alert.
Sending an alert twice is safe: the bot merges repeats into the open incident.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

APP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TIMEOUT = 5  # seconds for one request
ATTEMPTS = 4  # tries for the alert that just fired
BACKOFF = (2, 5, 15)  # seconds to wait between those tries
SPOOL_MAX_FILES = 50  # a bot that stays down for days cannot fill the disk
SPOOL_MAX_AGE = 24 * 3600  # seconds; an older alert is dropped instead of surfacing as a stale card
SPOOL_FLUSH_MAX = 10  # spooled alerts re-sent per run, so one run stays short

SENT, TEMPORARY, REJECTED = "sent", "temporary", "rejected"


def read(name):
    with open(os.path.join(APP, "local", name)) as f:
        return f.read().strip()


def log(level, message):
    print(f"{level} soc_bot_webhook {message}", file=sys.stderr)


def post(url, secret, body, timeout=TIMEOUT):
    """One POST. The HTTP status, or None when the bot could not be reached at all."""
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        method="POST",
        headers={"Content-Type": "application/json", "X-Webhook-Secret": secret},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:  # noqa: BLE001 - refused, reset, timeout, DNS: all mean "try again later"
        log("WARN", f"could not reach the bot ({type(e).__name__})")
        return None


def classify(status):
    if status is not None and 200 <= status < 300:
        return SENT
    if status is None or status in (408, 429) or status >= 500:
        return TEMPORARY  # bot down, restarting, overloaded or rate limiting: worth another try
    return REJECTED  # 400, 401, 403...: the same request will fail again, so never retry it


def deliver(url, secret, body, attempts=ATTEMPTS, backoff=BACKOFF, sleep=time.sleep):
    result = TEMPORARY
    for n in range(attempts):
        status = post(url, secret, body)
        result = classify(status)
        if result != TEMPORARY:
            if result == REJECTED:
                log("ERROR", f"the bot rejected the alert, HTTP {status}; not retrying")
            return result
        if n < attempts - 1:
            sleep(backoff[min(n, len(backoff) - 1)])
    return result


def spool_dir():
    return os.path.join(APP, "local", "spool")


def spool_files(directory):
    try:
        return sorted(n for n in os.listdir(directory) if n.endswith(".json"))
    except OSError:
        return []


def spool_add(directory, body, now=None):
    """Keep one alert for later. Holds the alert only, never the secret. Oldest files go first when the cap is hit."""
    os.makedirs(directory, mode=0o700, exist_ok=True)
    names = spool_files(directory)
    while len(names) >= SPOOL_MAX_FILES:
        os.remove(os.path.join(directory, names.pop(0)))
    stamp = int((time.time() if now is None else now) * 1000)
    name = f"{stamp:015d}-{os.getpid()}.json"
    path = os.path.join(directory, name)
    fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(body, f)
    os.replace(path + ".tmp", path)  # a half-written file is never picked up
    return path


def spool_flush(directory, url, secret, now=None, sleep=time.sleep):
    """Re-send queued alerts, oldest first. Stops at the first temporary failure: the bot is still down."""
    sent = 0
    now = time.time() if now is None else now
    for name in spool_files(directory)[:SPOOL_FLUSH_MAX]:
        path = os.path.join(directory, name)
        try:
            with open(path) as f:
                body = json.load(f)
        except (OSError, ValueError):
            _remove(path)  # unreadable: it would only fail again
            continue
        if now - os.path.getmtime(path) > SPOOL_MAX_AGE:
            log("WARN", f"dropping a queued alert older than {SPOOL_MAX_AGE // 3600} hours")
            _remove(path)
            continue
        result = deliver(url, secret, body, attempts=1, sleep=sleep)
        if result == TEMPORARY:
            break
        _remove(path)  # sent, or rejected for good
        sent += result == SENT
    if sent:
        log("INFO", f"re-sent {sent} queued alert(s)")
    return sent


def _remove(path):
    try:
        os.remove(path)
    except OSError:
        pass


def flush_only(sleep=time.sleep):
    """The scheduled re-send: no alert is firing, so only the queue is worked. Does nothing when the queue is empty."""
    if not spool_files(spool_dir()):
        return 0
    spool_flush(spool_dir(), read("url"), read("secret"), sleep=sleep)
    return 0


def main(argv=None, stdin=None, sleep=time.sleep):
    argv = sys.argv if argv is None else argv
    if len(argv) >= 2 and argv[1] == "--flush":
        return flush_only(sleep=sleep)
    if len(argv) < 2 or argv[1] != "--execute":
        print("FATAL unsupported mode, expected --execute or --flush", file=sys.stderr)
        return 2
    payload = json.loads((sys.stdin if stdin is None else stdin).read())
    body = {k: payload.get(k) for k in ("search_name", "result", "results_link")}
    url, secret = read("url"), read("secret")
    spool_flush(spool_dir(), url, secret, sleep=sleep)  # older alerts first, so cards keep their order
    result = deliver(url, secret, body, sleep=sleep)
    if result == SENT:
        log("INFO", "sent alert")
        return 0
    if result == TEMPORARY:
        try:
            spool_add(spool_dir(), body)
            log("ERROR", "the bot is unreachable; the alert is queued and will be re-sent within a few minutes")
        except OSError as e:
            log("ERROR", f"the bot is unreachable and the alert could not be queued ({type(e).__name__})")
    return 1  # Splunk records the failure; REJECTED was already logged


if __name__ == "__main__":
    sys.exit(main())
