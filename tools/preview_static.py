"""Dev-only: render the workspace markup to a static HTML file so the design can
be reviewed in a browser without starting the Streamlit server."""

import html
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import atlas_parser as ap  # noqa: E402

esc = html.escape

source = open(os.path.join(ROOT, "app.py"), encoding="utf-8").read()
css = re.search(r'CSS = """(.*?)"""', source, re.S).group(1)

sample = open(os.path.join(ROOT, "samples", "safe-example.log"), encoding="utf-8").read()
records, fmt, conf = ap.parse_log(sample)
incidents = ap.build_incidents(records)
stats = ap.summarise(records)


def badge(severity):
    cls = {"ERROR": "ERROR", "WARN": "WARN", "INFO": "INFO"}.get(severity, "OTHER")
    return f'<span class="badge {cls}">{esc(severity)}</span>'


def trunc(value, limit=156):
    value = value.strip()
    return value if len(value) <= limit else value[:limit].rstrip() + "…"


def incident_card(inc, selected=False):
    rec = inc.first
    tag = '<span class="tag">TRANSACTION</span>' if inc.is_transaction else ""
    exc = rec.exceptions[0].split(".")[-1] if rec.exceptions else ""
    exc_html = f'<span class="exc">{esc(exc)}</span>' if exc else ""
    cls = "st-key-card-sel" if selected else "st-key-card"
    return (
        f'<div class="{cls}" style="padding:12px 14px;margin-bottom:8px;display:flex;gap:10px;align-items:center;">'
        '<div style="flex:1 1 auto;min-width:0;">'
        '<div class="card-top">'
        f"{badge(inc.severity)}"
        f'<span class="mono-time">{esc(ap.human_time(inc.latest))}</span>{tag}'
        f'<span class="count">×{inc.count}</span></div>'
        f'<div class="card-title">{esc(trunc(ap.mask_text(inc.title)))}</div>'
        f'<div class="card-foot"><span>{esc(inc.component)}</span>{exc_html}</div>'
        "</div>"
        '<div class="btn small">Open</div>'
        "</div>"
    )


cards = "".join(
    incident_card(inc, selected=(i == 0)) for i, inc in enumerate(incidents)
)

selected = incidents[0].first if incidents else records[0]
facts = "".join(
    f"<div><dt>{esc(k)}</dt><dd>{esc(ap.mask_fact(k, v))}</dd></div>"
    for k, v in selected.facts.items()
)
exceptions = "".join(
    f"<div><span>{i + 1}</span><code>{esc(name)}</code></div>"
    for i, name in enumerate(selected.exceptions)
)

nav = ""
for label, count, active in (
    ("Errors &amp; warnings", len(incidents), True),
    ("Transactions", sum(1 for i in incidents if i.is_transaction), False),
    ("Operational signals", stats["healthy"], False),
    ("All grouped cases", len(incidents), False),
):
    style = (
        "background:rgba(226,96,61,.11);border-color:rgba(226,96,61,.34);color:#F4F8F5;"
        if active
        else "border-color:transparent;"
    )
    nav += (
        f'<div class="btn" style="justify-content:flex-start;{style}">'
        f'{"●" if active else "○"}&nbsp;&nbsp;{label} · {count}</div>'
    )

page = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Diagnostic Atlas preview</title>
{css}
<style>
body{{margin:0;background:#0A0E0D;color:#E9EFEB;font-family:var(--sans);}}
.shell{{display:grid;grid-template-columns:262px 1fr;min-height:100vh;}}
aside.rail{{background:#0B100F;border-right:1px solid var(--line);padding:20px 18px;}}
.btn{{display:flex;align-items:center;border:1px solid var(--line);border-radius:9px;
  padding:8px 11px;margin-bottom:6px;font:500 12.5px/1.3 var(--sans);color:var(--muted);}}
.btn.small{{font:500 10px/1 var(--mono);letter-spacing:.1em;text-transform:uppercase;
  padding:0 9px;height:28px;justify-content:center;width:76px;margin:0;}}
main{{padding:22px 34px 40px;}}
.topbar{{display:grid;grid-template-columns:1.5fr 1fr;gap:24px;align-items:start;}}
.controls{{display:flex;gap:8px;align-items:center;justify-content:flex-end;}}
.pill{{border:1px solid var(--line);border-radius:9px;background:rgba(255,255,255,.03);
  font:400 11.5px/1 var(--mono);color:#D8E2DC;padding:9px 12px;}}
.pill.toggle{{display:flex;align-items:center;gap:7px;color:#9FB0A8;}}
.knob{{width:26px;height:14px;border-radius:8px;background:rgba(226,96,61,.5);position:relative;}}
.knob:after{{content:"";position:absolute;right:2px;top:2px;width:10px;height:10px;border-radius:50%;background:#F4F8F5;}}
.search{{width:100%;box-sizing:border-box;background:rgba(255,255,255,.03);border:1px solid var(--line);
  border-radius:9px;padding:10px 12px;color:var(--dim);font:400 12.5px var(--sans);margin-bottom:4px;}}
.cols{{display:grid;grid-template-columns:1.02fr .98fr;gap:26px;margin-top:10px;}}
.cardrow{{display:grid;grid-template-columns:1fr 78px;gap:8px;align-items:center;}}
</style></head>
<body><div class="shell">
<aside class="rail">
  <div class="brand"><div class="mark"></div><div><b>Diagnostic Atlas</b><span>log triage workspace</span></div></div>
  <div style="height:34px"></div>
  <span class="rail-label">Investigation lens</span>
  {nav}
  <div class="privacy"><div class="stamp">● Local parsing</div>
    <p>Your file is parsed inside this Python process and never uploaded to a third party.
    Masking is applied before anything is displayed.</p></div>
</aside>
<main>
  <div class="topbar">
    <div>
      <span class="eyebrow">Diagnostic Atlas · case workspace</span>
      <div class="atlas-title">safe-example.log</div>
      <div class="subline">{len(records)} records · <b>{ap.FORMAT_LABELS[fmt]}</b> · {conf.lower()} confidence · {stats['errors']} errors</div>
    </div>
    <div class="controls">
      <div class="pill">Vista pipe-delimited ▾</div>
      <div class="pill toggle"><span class="knob"></span>Mask</div>
      <div class="pill">Export view</div>
    </div>
  </div>
  <div class="stats" style="margin-top:18px;">
    <div class="stat"><b>{len(records)}</b><span>records</span></div>
    <div class="stat"><b>{stats['errors']}</b><span>errors</span></div>
    <div class="stat"><b>{stats['warnings']}</b><span>warnings</span></div>
    <div class="stat"><b>{len(incidents)}</b><span>incident patterns</span></div>
    <div class="stat"><b>{stats['transactions']}</b><span>transaction records</span></div>
    <div class="stat"><b>{stats['healthy']}</b><span>healthy signals</span></div>
  </div>
  <div class="cols">
    <div>
      <span class="rail-label">Grouped incident stream</span>
      <div class="search">Search error, component, booking…</div>
      <div class="stream-count" style="margin:6px 0 10px;">{len(incidents)} visible</div>
      {''.join(incident_card(inc, i==0) for i, inc in enumerate(incidents))}
    </div>
    <div>
      <span class="rail-label">Case-file detail</span>
      <div class="case-head">
        <div class="case-flags">{badge(selected.severity)}{'<span class="tag">TRANSACTION</span>' if selected.is_transaction else ''}</div>
        <h3>{esc(selected.header)}</h3>
        <div class="case-stamps"><span>{esc(ap.human_time(selected.timestamp))}</span><span>{esc(selected.component)}</span><span>{esc(selected.fmt)}</span></div>
      </div>
      <div style="display:flex;gap:20px;border-bottom:1px solid var(--line);margin:18px 0 16px;">
        <span style="font:500 10.5px/1 var(--mono);letter-spacing:.13em;text-transform:uppercase;color:#F2F6F3;padding-bottom:11px;border-bottom:2px solid var(--oxide);margin-bottom:-1px;">Overview</span>
        <span style="font:500 10.5px/1 var(--mono);letter-spacing:.13em;text-transform:uppercase;color:var(--dim);padding-bottom:11px;">Transaction ({len(selected.facts)})</span>
        <span style="font:500 10.5px/1 var(--mono);letter-spacing:.13em;text-transform:uppercase;color:var(--dim);padding-bottom:11px;">Raw detail</span>
      </div>
      <span class="section-label">Error header</span>
      <p class="header-summary">{esc(selected.header)}</p>
      <div style="height:18px"></div>
      <span class="section-label">Event context</span>
      <dl class="meta-grid">
        <div><dt>Component</dt><dd>{esc(selected.component)}</dd></div>
        <div><dt>Correlation ID</dt><dd>{esc(ap.mask_text(selected.correlation_id))}</dd></div>
        <div><dt>Version</dt><dd>{esc(selected.version or '—')}</dd></div>
        <div><dt>Details</dt><dd>{selected.attached_lines} attached lines</dd></div>
      </dl>
      <div style="height:18px"></div>
      <span class="section-label">Exception chain</span>
      {f'<div class="exc-list">{exceptions}</div>' if exceptions else '<p class="quiet">No .NET exception class was extracted from this record.</p>'}
      <div style="height:18px"></div>
      <span class="section-label">Transaction facts</span>
      <dl class="facts">{facts}</dl>
    </div>
  </div>
</main></div></body></html>"""

out = os.path.join(HERE, "preview.html")
open(out, "w", encoding="utf-8").write(page)
print(out)

# ---------------------------------------------------------------- empty state
empty = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Diagnostic Atlas - empty state</title>
{css}
<style>
body{{margin:0;background:#0A0E0D;color:#E9EFEB;font-family:var(--sans);}}
.shell{{display:grid;grid-template-columns:262px 1fr;min-height:100vh;}}
aside.rail{{background:#0B100F;border-right:1px solid var(--line);padding:20px 18px;}}
main{{padding:26px 34px 40px;}}
.btn{{display:flex;align-items:center;justify-content:center;border:1px solid var(--line);
  border-radius:9px;padding:10px 14px;font:500 12px var(--sans);color:var(--muted);}}
.drop{{border:1px dashed rgba(232,240,236,.16);border-radius:14px;padding:26px;
  background:rgba(255,255,255,.018);}}
</style></head>
<body><div class="shell">
<aside class="rail">
  <div class="brand"><div class="mark"></div><div><b>Diagnostic Atlas</b><span>log triage workspace</span></div></div>
  <div style="height:34px"></div>
  <div class="drop" style="padding:18px;text-align:center;color:var(--dim);font:400 11.5px var(--sans);">Drag and drop file here<br><span style="font-size:10px">Limit 100MB per file · LOG, TXT, JSON</span></div>
  <div class="privacy"><div class="stamp">● Local parsing</div>
    <p>Your file is parsed inside this Python process and never uploaded to a third party.
    Masking is applied before anything is displayed.</p></div>
</aside>
<main>
  <div class="hero">
    <span class="eyebrow">Grouped by incident</span>
    <h2>Turn a wall of trace text into a clear case file.</h2>
    <p>Vista, JSON, bracketed application, syslog, and common timestamped logs are grouped into
    readable incident cases. Multiline stack traces stay attached to the header that caused them.</p>
  </div>
  <div style="display:grid;grid-template-columns:1.55fr 1fr;gap:24px;margin-top:18px;">
    <div>
      <div class="drop" style="text-align:center;">
        <div style="font:500 12.5px var(--sans);color:#DCE5DF;">Drop a .log, .txt or .json file here</div>
        <div class="btn" style="width:120px;margin:14px auto 0;">Browse files</div>
      </div>
      <div class="subline" style="margin-top:9px;">Auto-detect supports Vista, JSON, bracketed application, syslog, and timestamped logs.</div>
    </div>
    <div>
      <span class="rail-label">No file at hand?</span>
      <div class="subline" style="margin-bottom:10px;">Load a synthetic Vista log with two failures, one warning and two healthy signals.</div>
      <div class="btn" style="width:190px;">Explore a safe example</div>
    </div>
  </div>
  <section class="console">
    <div class="console-head"><div style="flex:1 1 340px;">
      <span class="eyebrow">Workspace preview</span>
      <h3>The investigation structure is ready before the file arrives.</h3></div>
      <span class="console-hint">header → detail</span></div>
    <div class="console-grid">
      <div class="console-col"><span class="rail-label">Grouped incident stream</span>
        <div class="mock-card"><div class="card-top"><span class="badge ERROR">ERROR</span>
          <span class="mono-time">00:20:04</span><span class="count">× 46</span></div>
          <div class="card-title">Send mail failed. See exception stack trace for details.</div>
          <div class="card-foot"><span>OnlineStoreEmailService</span><span class="exc">SmtpException</span></div></div>
        <div class="mock-card"><div class="card-top"><span class="badge ERROR">ERROR</span>
          <span class="mono-time">03:11:16</span><span class="tag">TRANSACTION</span><span class="count">× 1</span></div>
          <div class="card-title">Order completion failed after payment confirmation.</div>
          <div class="card-foot"><span>WSVistaWebClient</span><span class="exc">VSS response code 55</span></div></div>
        <div class="mock-card soft"><div class="card-top"><span class="badge WARN">WARN</span>
          <span class="mono-time">02:43:43</span><span class="count">× 2</span></div>
          <div class="card-title">Loyalty recognition discount values cannot sum to zero.</div>
          <div class="card-foot"><span>ApplyLoyaltyRecognitionDiscounts</span></div></div>
        <div class="mock-card soft"><div class="card-top"><span class="badge INFO">INFO</span>
          <span class="mono-time">03:00:57</span><span class="count">OK</span></div>
          <div class="card-title">WSVistaWebClient started</div>
          <div class="card-foot"><span>WSVistaWebClient</span><span class="ok">healthy signal</span></div></div>
      </div>
      <div class="console-col"><span class="rail-label">Case-file detail</span>
        <div class="mock-detail">
          <div class="mock-tabs"><span class="on">Overview</span><span>Transaction</span><span>Raw detail</span></div>
          <div class="mock-line" style="width:62%"></div>
          <div class="mock-line" style="width:88%"></div>
          <div class="mock-line" style="width:44%;margin-bottom:14px"></div>
          <div class="mock-line" style="width:74%"></div>
          <div class="mock-line" style="width:81%"></div>
          <div class="mock-line" style="width:57%;margin-bottom:0"></div>
        </div>
      </div>
    </div>
  </section>
</main></div></body></html>"""

out2 = os.path.join(HERE, "preview-empty.html")
open(out2, "w", encoding="utf-8").write(empty)
print(out2)
