#!/usr/bin/env python3
"""Splunk alert action: POST the first result row to the SOC Bot with the secret header."""
import json
import os
import sys
import urllib.error
import urllib.request

APP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(name):
    with open(os.path.join(APP, "local", name)) as f:
        return f.read().strip()


def main():
    if len(sys.argv) < 2 or sys.argv[1] != "--execute":
        print("FATAL unsupported mode, expected --execute", file=sys.stderr)
        return 2
    payload = json.loads(sys.stdin.read())
    body = {k: payload.get(k) for k in ("search_name", "result", "results_link")}
    req = urllib.request.Request(
        read("url"),
        data=json.dumps(body).encode(),
        method="POST",
        headers={"Content-Type": "application/json", "X-Webhook-Secret": read("secret")},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            print("INFO soc_bot_webhook sent alert, status=%s" % r.status, file=sys.stderr)
    except urllib.error.HTTPError as e:
        print("ERROR soc_bot_webhook HTTP %s" % e.code, file=sys.stderr)
        return 1
    except Exception as e:
        print("ERROR soc_bot_webhook %s" % type(e).__name__, file=sys.stderr)
        return 1
    return 0


sys.exit(main())
