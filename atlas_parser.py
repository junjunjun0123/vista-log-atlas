"""
atlas_parser.py
---------------
Python port of the parsing / grouping engine behind "Diagnostic Atlas".

Behaviour is intentionally kept close to the original app so that the same log
file produces the same incident cases:

  * format auto-detection (vista | json | bracketed | syslog | standard | generic)
  * record grouping: a "header" line starts a case, everything that does not
    look like a header stays attached to the case above it (stack traces, detail
    lines, quoted multi-line messages)
  * severity normalisation
  * fact extraction (booking / payment / transaction fields)
  * fingerprinting so repeated failures collapse into one incident with a count
  * masking of identifiers for safe sharing

No third-party dependencies.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable

# --------------------------------------------------------------------------- #
# Patterns
# --------------------------------------------------------------------------- #

LEVELS = r"TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|ERR|FATAL|CRITICAL"
_TS = r"\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}"

VISTA_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\|(?:"
    + LEVELS
    + r")\|",
    re.I,
)
BRACKET_RE = re.compile(
    r"^\[?"
    + _TS
    + r"(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\]?\s*\[(?:"
    + LEVELS
    + r")\]",
    re.I,
)
SYSLOG_RE = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+")
STANDARD_RE = re.compile(r"^" + _TS + r".*?\b(?:" + LEVELS + r")\b", re.I)
GENERIC_START_RE = re.compile(r"^(?:\[?" + _TS + r"|\[?(?:" + LEVELS + r")\b)", re.I)

FACT_KEYS = [
    "UserID",
    "CustomerID",
    "BookingRef",
    "BookingNumber",
    "TransactionNumber",
    "TransIdTemp",
    "APPLICATION_TRANSACTION",
    "Processing Step",
    "CinemaID",
    "ClientClass",
    "ErrorNo",
    "PaymentDetails",
]

SENSITIVE_FACT_KEYS = {
    "UserID",
    "CustomerID",
    "BookingRef",
    "BookingNumber",
    "TransactionNumber",
    "TransIdTemp",
    "APPLICATION_TRANSACTION",
    "OrderPaymentID",
    "CardNo",
}

TRANSACTION_FACT_KEYS = {
    "BookingRef",
    "BookingNumber",
    "TransactionNumber",
    "TransIdTemp",
    "APPLICATION_TRANSACTION",
    "Processing Step",
    "PaymentDetails",
}

FORMATS = [
    ("auto", "Auto-detect"),
    ("vista", "Vista pipe-delimited"),
    ("json", "JSON / JSONL"),
    ("bracketed", "Bracketed application"),
    ("syslog", "Syslog"),
    ("standard", "Timestamp + severity"),
    ("generic", "Generic multiline"),
]

FORMAT_LABELS = dict(FORMATS)


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass
class Record:
    index: int
    timestamp: str
    severity: str
    component: str
    header: str
    details: str
    raw: str
    version: str = ""
    correlation_id: str = ""
    facts: dict[str, str] = field(default_factory=dict)
    exceptions: list[str] = field(default_factory=list)
    is_transaction: bool = False
    is_success: bool = False
    fingerprint: str = ""
    fmt: str = ""

    @property
    def id(self) -> str:
        return f"{self.timestamp or 'untimed'}-{self.index}"

    @property
    def attached_lines(self) -> int:
        return len([ln for ln in self.details.split("\n") if ln.strip()])


@dataclass
class Incident:
    id: str
    severity: str
    component: str
    title: str
    count: int
    latest: str
    is_transaction: bool
    records: list[Record] = field(default_factory=list)

    @property
    def first(self) -> Record:
        return self.records[0]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def normalise_severity(raw: str) -> str:
    value = (raw or "").strip().upper()
    if value in {"ERROR", "ERR", "FATAL", "CRITICAL"}:
        return "ERROR"
    if value in {"WARN", "WARNING"}:
        return "WARN"
    if value in {"INFO", "NOTICE"}:
        return "INFO"
    if value == "DEBUG":
        return "DEBUG"
    if value == "TRACE":
        return "TRACE"
    return "OTHER"


def _split_pipe(line: str, pipes: int = 6) -> list[str]:
    parts: list[str] = []
    cursor = 0
    for _ in range(pipes):
        nxt = line.find("|", cursor)
        if nxt == -1:
            parts.append(line[cursor:])
            return parts
        parts.append(line[cursor:nxt])
        cursor = nxt + 1
    parts.append(line[cursor:])
    return parts


def _clean_message(text: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r'^"+|"+$', "", text or "")).strip()


def _dig(payload, dotted: Iterable[str]) -> str:
    for key in dotted:
        node = payload
        for part in key.split("."):
            if not isinstance(node, dict) or part not in node:
                node = None
                break
            node = node[part]
        if isinstance(node, (str, int, float)) and not isinstance(node, bool):
            return str(node)
    return ""


def extract_facts(text: str) -> dict[str, str]:
    facts: dict[str, str] = {}
    for key in FACT_KEYS:
        pattern = re.compile(re.escape(key) + r":\s*([^;\n|]+)", re.I)
        match = pattern.search(text)
        if match and match.group(1).strip():
            facts[key] = match.group(1).strip()

    http = re.search(r"(?:Response )?HTTP status:\s*([^\n|,]+)", text, re.I)
    if http and http.group(1).strip():
        facts["HTTP status"] = http.group(1).strip()

    app = re.search(r"Application:\s*([^\.\n|,]+)", text, re.I)
    if app and app.group(1).strip():
        facts["Application"] = app.group(1).strip()

    return facts


def _fingerprint(component: str, header: str) -> str:
    slug = re.sub(r"https?://[^\s,]+", "[endpoint]", header, flags=re.I)
    slug = re.sub(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", "[id]", slug, flags=re.I)
    slug = re.sub(r"\b\d{5,}\b", "[number]", slug)
    slug = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b", "[host]", slug)
    slug = re.sub(r"\s+", " ", slug).strip().lower()[:240]
    return f"{component}|{slug}"


def extract_exceptions(text: str) -> list[str]:
    found = re.findall(r"(?:[A-Za-z_][\w`]*\.)+[A-Za-z_][\w`]*(?:Exception|Error)\b", text)
    seen: list[str] = []
    for name in found:
        if name not in seen:
            seen.append(name)
    return seen[:5]


_TRANSACTION_KEYWORD_RE = re.compile(
    r"\b(?:order\.process(?:transcomplete|payment)|transcomplete|payment\s+(?:finish|authori[sz]ed|completed|made)"
    r"|booking(?:\s*(?:ref|number))?|transaction(?:\s*(?:id|number))?|paymentdetails|application_transaction)\b",
    re.I,
)
_TRANSACTION_ENTITY_RE = re.compile(
    r"\b(?:order|booking|ticket|payment|transaction)\b[^\n]{0,90}\b(?:failed|failure|error|timeout|timed out"
    r"|complete(?:d|ion)?|authori[sz]ed|reserve(?:d)?|set[- ]?tickets?)\b",
    re.I,
)
_ORDER_PATH_RE = re.compile(r"/orders/[^\s/]+(?:/|\b)", re.I)
_SUCCESS_RE = re.compile(
    r"\b(started|complete|completed|initialising|initializing|available|retrieved|selected"
    r"|binding complete|healthy|ready|connected|listening)\b",
    re.I,
)


def _build(
    *,
    index: int,
    timestamp: str,
    level: str,
    component: str,
    first_message: str,
    details: str,
    raw: str,
    fmt: str,
    version: str = "",
    correlation_id: str = "",
) -> Record:
    header = (_clean_message(first_message).split("\n")[0]) or "Untitled log event"
    corpus = f"{first_message}\n{details}"
    severity = normalise_severity(level)
    facts = extract_facts(corpus)

    is_transaction = (
        any(key in facts for key in TRANSACTION_FACT_KEYS)
        or bool(_ORDER_PATH_RE.search(corpus))
        or bool(_TRANSACTION_KEYWORD_RE.search(corpus))
        or bool(_TRANSACTION_ENTITY_RE.search(corpus))
    )
    is_success = severity == "INFO" and bool(_SUCCESS_RE.search(corpus))

    return Record(
        index=index,
        timestamp=timestamp,
        severity=severity,
        component=component or "Application",
        header=header,
        details=(details or "").strip(),
        raw=raw,
        version=version,
        correlation_id=correlation_id,
        facts=facts,
        exceptions=extract_exceptions(corpus),
        is_transaction=is_transaction,
        is_success=is_success,
        fingerprint=_fingerprint(component or "Application", header),
        fmt=fmt,
    )


# --------------------------------------------------------------------------- #
# Per-format record parsers
# --------------------------------------------------------------------------- #


def _parse_vista(group: list[str], index: int) -> Record:
    fields = _split_pipe(group[0], 6) + [""] * 7
    return _build(
        index=index,
        timestamp=fields[0],
        level=fields[1] or "OTHER",
        version=fields[2],
        correlation_id=fields[3],
        component=fields[5] or "Unknown",
        first_message=fields[6],
        details="\n".join(group[1:]),
        raw="\n".join(group),
        fmt="vista",
    )


def _parse_json(group: list[str], index: int) -> Record:
    try:
        payload = json.loads(group[0])
        if not isinstance(payload, dict):
            payload = {"message": group[0]}
    except Exception:
        payload = {"message": group[0]}

    ts = _dig(payload, ["@timestamp", "timestamp", "time", "datetime", "date"])
    level = _dig(payload, ["level", "severity", "log.level", "logLevel"])
    component = _dig(payload, ["logger", "component", "service", "source", "app", "log.logger"]) or "JSON log"
    message = _dig(payload, ["message", "msg", "event", "error.message"]) or json.dumps(payload)[:2000]
    detail_bits = [
        _dig(payload, ["stack", "trace", "error.stack", "exception.stacktrace", "exception"]),
        "\n".join(group[1:]),
    ]
    return _build(
        index=index,
        timestamp=ts,
        level=level or "OTHER",
        component=component,
        first_message=message,
        details="\n".join(bit for bit in detail_bits if bit),
        raw="\n".join(group),
        fmt="json",
    )


def _parse_bracketed(group: list[str], index: int) -> Record:
    match = re.match(
        r"^\[?(.+?)\]?\s+\[(" + LEVELS + r")\]\s*(?:\[([^\]]+)\]\s*)?(.*)$",
        group[0],
        re.I,
    )
    ts, level, component, message = ("", "OTHER", "Application", group[0])
    if match:
        ts = match.group(1) or ""
        level = match.group(2) or "OTHER"
        component = match.group(3) or "Application"
        message = match.group(4) or group[0]
    return _build(
        index=index,
        timestamp=ts,
        level=level,
        component=component,
        first_message=message,
        details="\n".join(group[1:]),
        raw="\n".join(group),
        fmt="bracketed",
    )


def _parse_syslog(group: list[str], index: int) -> Record:
    match = re.match(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+([^:]+):\s*(.*)$", group[0])
    ts, component, message = "", "syslog", group[0]
    if match:
        ts = match.group(1) or ""
        component = match.group(2) or "syslog"
        message = match.group(3) or group[0]
    level_match = re.search(r"\b(" + LEVELS + r")\b", message, re.I)
    level = level_match.group(1) if level_match else "OTHER"
    if level_match:
        message = re.sub(r"\b" + re.escape(level_match.group(1)) + r"\b[:\s-]*", "", message, count=1, flags=re.I)
    return _build(
        index=index,
        timestamp=ts,
        level=level,
        component=component,
        first_message=message,
        details="\n".join(group[1:]),
        raw="\n".join(group),
        fmt="syslog",
    )


def _parse_standard(group: list[str], index: int, fmt: str) -> Record:
    line = group[0]
    match = re.match(
        r"^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
        r"(?:\[(" + LEVELS + r")\]|(" + LEVELS + r"))\s*"
        r"(?:\[([^\]]+)\]\s*)?"
        r"(?:([A-Za-z][\w.-]+)\s*[-:]\s*)?"
        r"(.*)$",
        line,
        re.I,
    )
    loose = re.search(r"\b(" + LEVELS + r")\b", line, re.I)
    ts = component = ""
    level = "OTHER"
    message = line
    if match:
        ts = match.group(1) or ""
        level = match.group(2) or match.group(3) or "OTHER"
        component = match.group(4) or match.group(5) or "Application"
        message = match.group(6) or line
    else:
        ts_match = re.match(r"^\[?([^\s\]]+(?:\s+[^\s\]]+)?)?", line)
        ts = ts_match.group(1) if ts_match else ""
        if loose:
            level = loose.group(1)
            message = re.sub(r"^.*?\b" + re.escape(loose.group(1)) + r"\b[:\s-]*", "", line, count=1, flags=re.I)
    return _build(
        index=index,
        timestamp=ts,
        level=level,
        component=component,
        first_message=message,
        details="\n".join(group[1:]),
        raw="\n".join(group),
        fmt=fmt,
    )


# --------------------------------------------------------------------------- #
# Detection + entry points
# --------------------------------------------------------------------------- #


def detect_format(text: str, override: str = "auto") -> tuple[str, str]:
    if override != "auto":
        return override, "High"

    lines = [ln for ln in re.sub(r"\r\n?", "\n", text).split("\n") if ln.strip()][:100]
    if not lines:
        return "generic", "Fallback"

    json_candidates = [ln for ln in lines if ln.strip().startswith("{")][:50]
    if json_candidates:
        ok = 0
        for line in json_candidates:
            try:
                parsed = json.loads(line)
                if isinstance(parsed, dict):
                    ok += 1
            except Exception:
                pass
        if ok >= max(1, math.ceil(len(lines) * 0.65)):
            return "json", "High"

    if any(VISTA_RE.match(ln) for ln in lines):
        return "vista", "High"
    if any(BRACKET_RE.match(ln) for ln in lines):
        return "bracketed", "High"
    if any(SYSLOG_RE.match(ln) for ln in lines):
        return "syslog", "Medium"
    if any(STANDARD_RE.match(ln) for ln in lines):
        return "standard", "Medium"
    return "generic", "Fallback"


def _is_record_start(line: str, fmt: str) -> bool:
    if not line.strip():
        return False
    if fmt == "vista":
        return bool(VISTA_RE.match(line))
    if fmt == "json":
        if not line.strip().startswith("{"):
            return False
        try:
            json.loads(line)
            return True
        except Exception:
            return False
    if fmt == "bracketed":
        return bool(BRACKET_RE.match(line))
    if fmt == "syslog":
        return bool(SYSLOG_RE.match(line))
    if fmt == "standard":
        return bool(STANDARD_RE.match(line))
    return bool(GENERIC_START_RE.match(line))


def parse_log(text: str, override: str = "auto") -> tuple[list[Record], str, str]:
    """Return (records, format, confidence)."""
    fmt, confidence = detect_format(text, override)

    lines = re.sub(r"\r\n?", "\n", text).split("\n")
    groups: list[list[str]] = []
    current: list[str] = []

    for line in lines:
        if _is_record_start(line, fmt):
            if current:
                groups.append(current)
            current = [line]
        elif current:
            current.append(line)
        elif line.strip():
            current = [line]

    if current:
        groups.append(current)

    records: list[Record] = []
    for idx, group in enumerate(groups):
        if fmt == "vista":
            records.append(_parse_vista(group, idx))
        elif fmt == "json":
            records.append(_parse_json(group, idx))
        elif fmt == "bracketed":
            records.append(_parse_bracketed(group, idx))
        elif fmt == "syslog":
            records.append(_parse_syslog(group, idx))
        else:
            records.append(_parse_standard(group, idx, fmt))

    return records, fmt, confidence


def _sort_key(timestamp: str):
    parsed = parse_timestamp(timestamp)
    if parsed is None:
        return (1, timestamp or "")
    return (0, parsed.isoformat())


def build_incidents(records: list[Record]) -> list[Incident]:
    buckets: dict[str, Incident] = {}
    for record in records:
        if record.severity not in {"ERROR", "WARN"}:
            continue
        bucket = buckets.get(record.fingerprint)
        if bucket is None:
            buckets[record.fingerprint] = Incident(
                id=record.fingerprint,
                severity=record.severity,
                component=record.component,
                title=record.header,
                count=1,
                latest=record.timestamp,
                is_transaction=record.is_transaction,
                records=[record],
            )
        else:
            bucket.records.append(record)
            bucket.count += 1
            if _sort_key(record.timestamp) > _sort_key(bucket.latest):
                bucket.latest = record.timestamp

    return sorted(buckets.values(), key=lambda inc: _sort_key(inc.latest), reverse=True)


# --------------------------------------------------------------------------- #
# Masking + formatting
# --------------------------------------------------------------------------- #

_MASK_FACT_RULES = [
    (re.compile(r"(CardNo:\s*)[^;\n]+", re.I), r"\1[masked]"),
    (
        re.compile(
            r"((?:UserID|CustomerID|BookingRef|BookingNumber|TransactionNumber|TransIdTemp"
            r"|APPLICATION_TRANSACTION|OrderPaymentID):\s*)[^;\n]+",
            re.I,
        ),
        r"\1[masked]",
    ),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"), "[internal-host]"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", re.I), "[correlation-id]"),
    (re.compile(r"\b[0-9a-f]{32}\b", re.I), "[correlation-id]"),
]


def mask_text(value: str) -> str:
    if not value:
        return value
    out = value
    for pattern, replacement in _MASK_FACT_RULES:
        out = pattern.sub(replacement, out)
    return out


def mask_fact(key: str, value: str) -> str:
    if key in SENSITIVE_FACT_KEYS:
        return "[masked]"
    return mask_text(value)


def parse_timestamp(value: str) -> datetime | None:
    raw = (value or "").strip().strip("[]")
    if not raw:
        return None
    raw = raw.replace(",", ".")
    # Trim over-long fractional seconds (Vista uses 7 digits) to microseconds.
    raw = re.sub(r"\.(\d{6})\d+", r".\1", raw)
    for candidate in (
        raw,
        raw.replace(" ", "T", 1) if " " in raw else raw,
        re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", raw),
    ):
        try:
            return datetime.fromisoformat(candidate)
        except Exception:
            continue
    for fmt in ("%b %d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S"):
        try:
            return datetime.strptime(raw, fmt)
        except Exception:
            continue
    return None


def human_time(value: str) -> str:
    parsed = parse_timestamp(value)
    if parsed is None:
        return value or "Unstamped"
    return parsed.strftime("%d %b, %H:%M:%S")


def summarise(records: list[Record]) -> dict[str, int]:
    return {
        "records": len(records),
        "errors": sum(1 for r in records if r.severity == "ERROR"),
        "warnings": sum(1 for r in records if r.severity == "WARN"),
        "transactions": sum(1 for r in records if r.is_transaction),
        "healthy": sum(1 for r in records if r.is_success),
    }
