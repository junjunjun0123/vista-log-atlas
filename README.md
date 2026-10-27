# Diagnostic Atlas — Streamlit port

A local log-triage workspace: drop a raw log, get **grouped incident cases** instead of a
wall of trace text.

This is a Streamlit rebuild of the Manus-hosted app at
`vistaloganlz-q7dyqdld.manus.space`. The parsing engine was ported from that app's
bundle, so the same file produces the same cases, the same fingerprints, the same counts.

---

## Run it

```bash
pip install -r requirements.txt
streamlit run app.py
```

Opens on <http://127.0.0.1:8501>. No file leaves the machine — everything is parsed in the
Streamlit process.

Want the demo case file on boot?

```bash
# Windows (PowerShell)
$env:ATLAS_DEMO=1; streamlit run app.py
# macOS / Linux
ATLAS_DEMO=1 streamlit run app.py
```

---

## What it does

**1. Format detection** (`atlas_parser.detect_format`)

| Format | How it is recognised |
| --- | --- |
| JSON / JSONL | ≥65% of the first 100 lines parse as JSON objects |
| Vista pipe-delimited | `2026-08-17T03:11:16.49+08:00\|ERROR\|500.1329.0.1\|…` |
| Bracketed application | `[2026-08-17 03:11:16] [ERROR] [Component] message` |
| Syslog | `Aug 17 03:11:16 host app: message` |
| Timestamp + severity | `2026-08-17 03:11:16 ERROR …` |
| Generic multiline | fallback: any line starting with a timestamp or a severity token |

The detection is overridable from the header dropdown; confidence (High / Medium /
Fallback) is shown next to the file name.

**2. Incident grouping** (`parse_log`)

A line that matches the format's *header* pattern starts a case. Every following line that
does **not** look like a header — stack frames, quoted multi-line messages, detail
lines — is appended to the case above it. That is what keeps
`at void System.Net.Mail.SmtpClient.Send(...)` attached to the SMTP failure that caused it.

**3. Normalisation + evidence** (`Record`)

* severity → `ERROR / WARN / INFO / DEBUG / TRACE / OTHER`
* facts pulled from header + detail: `BookingRef`, `BookingNumber`, `TransactionNumber`,
  `TransIdTemp`, `APPLICATION_TRANSACTION`, `Processing Step`, `CinemaID`, `ClientClass`,
  `ErrorNo`, `PaymentDetails`, `HTTP status`, `Application`
* `.NET` exception classes extracted from the text (up to 5, de-duplicated)
* `is_transaction` / `is_success` heuristics for the lens filters

**4. Fingerprinting** (`build_incidents`)

Header text is normalised — URLs → `[endpoint]`, UUIDs → `[id]`, 5+ digit runs →
`[number]`, IPs → `[host]` — then hashed with the component. 46 identical SMTP failures
collapse into one card with `×46`, sorted by most recent occurrence.

**5. Masking** (`mask_text`)

`CardNo`, `UserID`, `CustomerID`, `BookingRef`, `BookingNumber`, `TransactionNumber`,
`TransIdTemp`, `APPLICATION_TRANSACTION`, `OrderPaymentID` → `[masked]`; IPs →
`[internal-host]`; UUID / 32-hex → `[correlation-id]`. Applied to everything on screen and
in the export, toggleable in the header.

---

## UI map

| Original | Here |
| --- | --- |
| Left rail, "Investigation lens" | sidebar: Errors & warnings / Transactions / Operational signals / All grouped cases, each with a live count |
| Top bar: file name, format select, masking toggle, export | same four controls, plus a JSON export of the current view |
| Grouped incident stream + search | left column: severity badge, time, `TRANSACTION` tag, `×count`, header, component, exception |
| Case-file detail: Overview / Transaction / Raw detail | right column tabs — error header, event context, exception chain; extracted facts; the preserved raw block with a copy button |

---

## Files

```
diagnostic-atlas/
├── app.py                  # Streamlit UI (CSS + layout + state)
├── atlas_parser.py         # detection, grouping, facts, fingerprints, masking
├── run.py                  # optional launcher (selector event loop on Windows)
├── requirements.txt
├── .streamlit/config.toml  # dark theme, localhost bind, watcher off
├── samples/safe-example.log
└── tools/preview_static.py # dev-only: renders the markup to static HTML for design review
```

The parser has no third-party dependencies — it can be reused in a CLI or a test suite:

```python
import atlas_parser as ap

records, fmt, confidence = ap.parse_log(open("app.log").read())
for incident in ap.build_incidents(records):
    print(f"x{incident.count} {incident.severity} {incident.title}")
```

---

## Deploy to Streamlit Community Cloud

1. Push this folder to a GitHub repo.
2. <https://share.streamlit.io> → New app → pick the repo → main file `app.py`.
3. Nothing else to configure: no secrets, no network calls, no storage.

---

## Notes / troubleshooting

* `.streamlit/config.toml` binds to `127.0.0.1` and disables the file watcher. Binding to
  localhost stops Streamlit from looking up the machine's external IP on startup, and the
  watcher is off because `watchdog`'s Windows directory-change reader crashed on the
  machine this was built on. Re-enable with `fileWatcherType = "auto"` if you want hot
  reload while editing.
* `run.py` is only needed if you hit an `asyncio` access violation on Windows; plain
  `streamlit run app.py` is the normal path.
* Large files: parsing is linear and cached per (file, format) pair. A few hundred
  thousand lines is fine; the UI only renders the visible lens.
