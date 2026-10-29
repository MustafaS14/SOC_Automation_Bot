"""Turn the assistant's technical answer into blocks the page can lay out neatly.

Tool results come back as one line of `key=value; key=value` (or `label: value; label: value`). Shown as they are,
they are hard to read, so they become labelled rows or a table. Anything that does not look like that, which is
most of what a real model writes, stays as plain paragraphs. Every value is plain text, escaped by the template.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import ClassVar

LABELS = {
    "rule": "Rule", "severity": "Severity", "status": "Status", "classification": "Classification", "host": "Host",
    "src_ip": "Source IP", "ip": "IP address", "assignee": "Assignee", "created": "Created", "updated": "Updated",
    "comments": "Comments", "description": "Description", "open incidents": "Open incidents",
    "by status": "By status", "open by severity": "Open by severity", "verdict": "Verdict", "public": "Public address",
    "abuse_score": "Abuse score", "vt_malicious": "VirusTotal malicious", "country": "Country", "errors": "Problems",
    "_time": "Time", "_raw": "Event",
}
# Lines that become a labelled row in the assessment block, in the order they are usually written.
ROW_LABELS = ("verdict", "evidence", "recommendation", "next step", "confidence", "not checked", "description")

_ROW = re.compile(r"^\s*(" + "|".join(re.escape(x) for x in ROW_LABELS) + r")\s*:\s*(.+?)\s*$", re.IGNORECASE)
_TITLE = re.compile(r"^\s*(?:(incident #\d+)\s*:|(#\d+))\s+", re.IGNORECASE)
_EQ = re.compile(r"^([A-Za-z_][A-Za-z_]{0,30})=(.*)$", re.DOTALL)
_COLON = re.compile(r"^([A-Za-z][A-Za-z ]{1,24}): (.*)$", re.DOTALL)
_LEVEL = re.compile(r"^(low|medium|high)\b[\s,.:;-]*(.*)$", re.IGNORECASE)


@dataclass
class Facts:
    kind: ClassVar[str] = "facts"
    title: str | None
    pairs: list[tuple[str, str]]


@dataclass
class Table:
    kind: ClassVar[str] = "table"
    columns: list[str]
    rows: list[list[str]]


@dataclass
class Row:
    label: str
    value: str
    level: str | None = None  # for Confidence: low, medium or high


@dataclass
class Rows:
    """Labelled lines such as Confidence and Not checked, shown together."""

    kind: ClassVar[str] = "rows"
    items: list[Row]


@dataclass
class Para:
    kind: ClassVar[str] = "para"
    text: str


@dataclass
class Parsed:
    blocks: list[object] = field(default_factory=list)


def pretty(key: str) -> str:
    key = key.strip()
    return LABELS.get(key.lower()) or LABELS.get(key) or key.replace("_", " ").strip().capitalize()


def _pairs(line: str) -> tuple[str | None, list[tuple[str, str]]] | None:
    """(title, pairs) if the whole line is made of key=value or label: value segments, else None."""
    title = None
    match = _TITLE.match(line)
    if match:
        title = (match.group(1) or match.group(2)).capitalize()
        line = line[match.end():]
    pairs: list[list[str]] = []
    for segment in line.split("; "):
        found = _EQ.match(segment) or _COLON.match(segment)
        if found:
            pairs.append([found.group(1), found.group(2).strip()])
        elif pairs:
            pairs[-1][1] += "; " + segment  # a value that itself contained "; "
        else:
            return None
    if len(pairs) < 2 and not (title and pairs):
        return None
    return title, [(k, v) for k, v in pairs]


def parse_answer(text: str) -> Parsed:
    blocks: list[object] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        row = _ROW.match(line)
        if row and row.group(1).lower() == "description" and blocks and isinstance(blocks[-1], Facts):
            blocks[-1].pairs.append(("description", row.group(2)))  # it belongs with the incident's other fields
            continue
        if row:
            label, value = row.group(1).lower(), row.group(2)
            level = None
            if label == "confidence":
                found = _LEVEL.match(value)
                if found:
                    level, value = found.group(1).lower(), found.group(2).strip()
            blocks.append(Row(label.capitalize(), value, level))
            continue
        parsed = _pairs(line)
        if parsed:
            blocks.append(Facts(parsed[0], parsed[1]))
        else:
            blocks.append(Para(line))
    return Parsed(_rows(_group(blocks)))


def _group(blocks: list[object]) -> list[object]:
    """Several fact lines with the same fields become one table."""
    grouped: list[object] = []
    i = 0
    while i < len(blocks):
        block = blocks[i]
        if isinstance(block, Facts):
            keys = [k for k, _ in block.pairs]
            run = [block]
            while i + len(run) < len(blocks):
                nxt = blocks[i + len(run)]
                if isinstance(nxt, Facts) and [k for k, _ in nxt.pairs] == keys and bool(nxt.title) == bool(block.title):
                    run.append(nxt)
                else:
                    break
            if len(run) >= 2:
                columns = (["#"] if block.title else []) + [pretty(k) for k in keys]
                rows = [([f.title or ""] if f.title else []) + [v for _, v in f.pairs] for f in run]
                grouped.append(Table(columns, rows))
                i += len(run)
                continue
        grouped.append(block)
        i += 1
    return grouped


def _rows(blocks: list[object]) -> list[object]:
    """Consecutive labelled lines (Confidence, Not checked, ...) become one block."""
    out: list[object] = []
    for block in blocks:
        if isinstance(block, Row):
            if out and isinstance(out[-1], Rows):
                out[-1].items.append(block)
            else:
                out.append(Rows([block]))
        else:
            out.append(block)
    return out
