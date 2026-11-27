#!/usr/bin/env python3
"""Scheduled re-send of queued alerts. Splunk runs this as a scripted input (default/inputs.conf), every two minutes.

It prints nothing on stdout, so nothing is indexed. It does nothing when the queue is empty. The work is in
soc_bot_webhook.py, which also holds the queue rules (oldest first, 10 a run, nothing older than 24 hours).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import soc_bot_webhook  # noqa: E402

if __name__ == "__main__":
    sys.exit(soc_bot_webhook.main([sys.argv[0], "--flush"]))
