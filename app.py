"""
Diagnostic Atlas - Streamlit port
=================================

A local, no-upload log triage workspace:

    raw log  ->  grouped incident cases  ->  one readable case file

Streamlit equivalent of the Manus-hosted "Diagnostic Atlas" app, with the same
parsing engine (see atlas_parser.py): format auto-detection, header/continuation
grouping, severity normalisation, fact extraction, fingerprint grouping and
identifier masking.

Run:
    streamlit run app.py
"""

from __future__ import annotations

import html
import hashlib
import json
import os
from datetime import datetime

import streamlit as st

import atlas_parser as ap

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLE_PATH = os.path.join(BASE_DIR, "samples", "safe-example.log")

st.set_page_config(
    page_title="Diagnostic Atlas",
    page_icon="🗂️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --------------------------------------------------------------------------- #
# Styling
# --------------------------------------------------------------------------- #

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500;600&display=swap');

:root{
  --bg:#0A0E0D;
  --panel:#0F1514;
  --line:rgba(232,240,236,.09);
  --line-soft:rgba(232,240,236,.055);
  --ink:#E9EFEB;
  --muted:#8A9992;
  --dim:#5E6C66;
  --oxide:#E2603D;
  --amber:#D9A441;
  --teal:#43A98C;
  --serif:'Iowan Old Style','Palatino Linotype',Palatino,Georgia,'Times New Roman',serif;
  --mono:'IBM Plex Mono',ui-monospace,'Cascadia Mono',Consolas,monospace;
  --sans:'Inter','Segoe UI',system-ui,-apple-system,sans-serif;
}

.stApp{
  background:
    radial-gradient(1100px 620px at 6% -14%, #16211E 0%, rgba(10,14,13,0) 62%),
    radial-gradient(900px 500px at 100% 0%, #141A18 0%, rgba(10,14,13,0) 55%),
    #0A0E0D;
}
header[data-testid="stHeader"]{background:transparent;}
[data-testid="stToolbar"]{right:.6rem;}
.block-container{padding:1.1rem 2.4rem 3.5rem;max-width:1560px;}
#MainMenu, footer{visibility:hidden;}

/* ---------------- sidebar ---------------- */
section[data-testid="stSidebar"]{
  background:#0B100F;border-right:1px solid var(--line);
}
section[data-testid="stSidebar"] .block-container,
section[data-testid="stSidebar"] > div{padding-top:.2rem;}

.brand{display:flex;gap:11px;align-items:center;padding:8px 2px 16px;}
.brand .mark{
  width:27px;height:27px;border-radius:8px;flex:0 0 auto;
  background:linear-gradient(150deg,#E2603D 0%,#8E3A22 100%);
  box-shadow:inset 0 0 0 1px rgba(255,255,255,.16), 0 4px 14px rgba(226,96,61,.22);
}
.brand b{display:block;font:600 12px/1.2 var(--sans);letter-spacing:.15em;text-transform:uppercase;color:#F0F5F2;}
.brand span{display:block;font:400 10px/1.5 var(--mono);letter-spacing:.09em;color:var(--dim);}

.rail-label{font:500 9.5px/1 var(--mono);letter-spacing:.17em;text-transform:uppercase;color:var(--dim);display:block;margin:0 0 9px 2px;}
.sidebar-rule{height:1px;background:var(--line);margin:16px 0;}

.privacy{margin-top:18px;border-top:1px solid var(--line-soft);padding-top:13px;}
.privacy .stamp{display:flex;align-items:center;gap:6px;font:500 10px/1 var(--mono);letter-spacing:.1em;text-transform:uppercase;color:#63C4A5;}
.privacy p{margin:7px 0 0;font:400 10.5px/1.55 var(--sans);color:var(--dim);}

/* lens nav buttons */
div[class*="st-key-lens-"] button{
  justify-content:flex-start;background:transparent;border:1px solid transparent;
  color:var(--muted);border-radius:9px;padding:8px 11px;min-height:0;height:auto;
  font:500 12.5px/1.3 var(--sans);width:100%;
}
div[class*="st-key-lens-"] button p{text-align:left;width:100%;font-size:12.5px;}
div[class*="st-key-lens-"] button:hover{background:rgba(255,255,255,.045);color:#F0F5F2;border-color:transparent;}

/* ---------------- typography helpers ---------------- */
.eyebrow{font:500 10px/1 var(--mono);letter-spacing:.19em;text-transform:uppercase;color:var(--dim);}
.atlas-title{font:400 30px/1.16 var(--serif);letter-spacing:-.012em;color:#F2F6F3;margin:9px 0 6px;}
.subline{font:400 11px/1.6 var(--mono);color:var(--dim);letter-spacing:.03em;}
.subline b{color:#A9B7B0;font-weight:500;}

/* ---------------- hero / empty state ---------------- */
.hero{
  border:1px solid var(--line);border-radius:16px;padding:34px 34px 30px;
  background:linear-gradient(160deg,rgba(226,96,61,.07),rgba(255,255,255,.012) 42%),#0E1413;
  position:relative;overflow:hidden;
}
.hero:before{
  content:"";position:absolute;inset:0;
  background:repeating-linear-gradient(90deg,rgba(255,255,255,.022) 0 1px,transparent 1px 64px);
  pointer-events:none;
}
.hero h2{font:400 33px/1.2 var(--serif);letter-spacing:-.015em;color:#F4F8F5;margin:12px 0 12px;max-width:26ch;}
.hero p{font:400 13px/1.7 var(--sans);color:#A5B3AC;max-width:64ch;margin:0;}

/* ---------------- stat strip ---------------- */
.stats{display:flex;gap:10px;flex-wrap:wrap;margin:2px 0 4px;}
.stat{border:1px solid var(--line);border-radius:11px;padding:11px 16px;background:rgba(255,255,255,.018);min-width:118px;}
.stat b{display:block;font:400 21px/1 var(--serif);color:#F2F6F3;}
.stat span{display:block;margin-top:6px;font:400 9.5px/1 var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--dim);}

/* ---------------- incident cards ---------------- */
div[class*="st-key-card"]{
  border:1px solid var(--line);border-radius:12px;
  background:linear-gradient(180deg,rgba(255,255,255,.024),rgba(255,255,255,.004));
  padding:12px 14px;transition:border-color .15s ease,background .15s ease;
}
div[class*="st-key-card"]:hover{border-color:rgba(226,96,61,.32);}
div[class*="st-key-card"] [data-testid="stVerticalBlock"]{gap:.15rem;}
div[class*="st-key-card-sel"]{
  border-color:rgba(226,96,61,.5);
  background:linear-gradient(180deg,rgba(226,96,61,.1),rgba(226,96,61,.015));
  box-shadow:inset 2px 0 0 var(--oxide);
}
.card-top{display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap;}
.mono-time{font:400 10.5px/1 var(--mono);color:var(--dim);letter-spacing:.04em;}
.tag{font:600 8.5px/1 var(--mono);letter-spacing:.13em;color:#63C4A5;border:1px solid rgba(67,169,140,.34);padding:3px 5px;border-radius:3px;}
.count{margin-left:auto;font:500 11px/1 var(--mono);color:var(--muted);}
.card-title{font:500 13.5px/1.45 var(--sans);color:#E9EFEB;}
.card-foot{display:flex;gap:10px;margin-top:8px;font:400 10.5px/1 var(--mono);color:var(--dim);flex-wrap:wrap;}
.card-foot .exc{color:rgba(226,96,61,.9);}
.card-foot .ok{color:rgba(67,169,140,.9);}

.badge{font:600 9px/1 var(--mono);letter-spacing:.13em;padding:3.5px 6px;border-radius:4px;border:1px solid;display:inline-block;}
.badge.ERROR{color:#F08A66;border-color:rgba(226,96,61,.45);background:rgba(226,96,61,.13);}
.badge.WARN{color:#E5B963;border-color:rgba(217,164,65,.45);background:rgba(217,164,65,.12);}
.badge.INFO{color:#63C4A5;border-color:rgba(67,169,140,.4);background:rgba(67,169,140,.12);}
.badge.OTHER{color:#8A9992;border-color:var(--line);background:rgba(255,255,255,.03);}

/* ---------------- case file ---------------- */
.case-head{
  border:1px solid var(--line);border-radius:13px;padding:17px 19px;
  background:linear-gradient(170deg,rgba(255,255,255,.032),rgba(255,255,255,.006));
}
.case-flags{display:flex;gap:8px;align-items:center;}
.case-head h3{font:400 19px/1.4 var(--serif);color:#F4F8F5;margin:11px 0 9px;letter-spacing:-.005em;}
.case-stamps{display:flex;gap:14px;font:400 10.5px/1 var(--mono);color:var(--dim);flex-wrap:wrap;}

.section-label{display:block;font:500 9.5px/1 var(--mono);letter-spacing:.16em;text-transform:uppercase;color:var(--dim);margin:0 0 8px;}
.header-summary{font:400 13.5px/1.6 var(--sans);color:#DCE5DF;margin:0;}

.meta-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px 20px;margin:0;}
.meta-grid > div{border-top:1px solid var(--line-soft);padding-top:8px;}
.meta-grid dt{font:400 9px/1 var(--mono);letter-spacing:.13em;text-transform:uppercase;color:var(--dim);}
.meta-grid dd{margin:6px 0 0;font:400 11.5px/1.5 var(--mono);color:#D8E2DC;word-break:break-word;}

.exc-list{display:grid;gap:7px;}
.exc-list > div{display:flex;gap:9px;align-items:baseline;}
.exc-list span{font:500 9px/1 var(--mono);color:var(--oxide);border:1px solid rgba(226,96,61,.38);border-radius:3px;padding:2px 4px;flex:0 0 auto;}
.exc-list code{font:400 11.5px/1.45 var(--mono);color:#DCE5DF;word-break:break-all;}
.quiet{font:400 11.5px/1.6 var(--sans);color:var(--dim);margin:0;}

.facts{display:grid;gap:9px;margin:0;}
.facts > div{display:grid;grid-template-columns:148px 1fr;gap:12px;border-bottom:1px dashed var(--line-soft);padding-bottom:8px;}
.facts dt{font:400 10.5px/1.55 var(--mono);color:var(--dim);letter-spacing:.04em;}
.facts dd{margin:0;font:400 11.5px/1.55 var(--mono);color:#E4EBE6;word-break:break-word;}

.callout{display:flex;gap:11px;border:1px solid rgba(67,169,140,.28);background:rgba(67,169,140,.08);border-radius:10px;padding:12px 14px;margin-bottom:14px;}
.callout.muted{border-color:var(--line);background:rgba(255,255,255,.02);}
.callout strong{display:block;font:500 12.5px/1.4 var(--sans);color:#DCE5DF;}
.callout p{margin:5px 0 0;font:400 11px/1.55 var(--sans);color:var(--dim);}
.callout .dot{width:7px;height:7px;border-radius:50%;background:var(--teal);margin-top:6px;flex:0 0 auto;}
.callout.muted .dot{background:var(--dim);}

/* ---------------- stream toolbar ---------------- */
.stream-count{font:400 10.5px/1 var(--mono);color:var(--dim);letter-spacing:.06em;}

/* ---------------- widgets ---------------- */
div[data-testid="stButton"] > button,
.stButton > button{
  background:rgba(255,255,255,.028);border:1px solid var(--line);color:var(--muted);
  border-radius:9px;font:500 11.5px/1 var(--sans);transition:all .15s ease;
}
div[data-testid="stButton"] > button:hover,
.stButton > button:hover{border-color:rgba(226,96,61,.45);color:#F4F8F5;background:rgba(226,96,61,.09);}
div[data-testid="stButton"] > button:focus:not(:active),
.stButton > button:focus:not(:active){border-color:rgba(226,96,61,.45);color:#F4F8F5;box-shadow:none;}
div[data-testid="stButton"] > button p,
.stButton > button p{margin:0;line-height:1.2;}
div[class*="st-key-card"] div[data-testid="stButton"] > button,
div[class*="st-key-card"] .stButton button{
  min-height:28px;height:28px;padding:0 9px;font:500 10px/1 var(--mono);
  letter-spacing:.1em;text-transform:uppercase;
}

.stTextInput input{
  background:rgba(255,255,255,.03);border:1px solid var(--line);border-radius:9px;
  color:#E9EFEB;font:400 12.5px/1 var(--sans);padding:9px 11px;
}
.stTextInput input::placeholder{color:var(--dim);}
.stTextInput input:focus{border-color:rgba(226,96,61,.45);box-shadow:none;}

div[data-baseweb="select"] > div{
  background:rgba(255,255,255,.03);border:1px solid var(--line);border-radius:9px;
  font:400 11.5px/1 var(--mono);color:#D8E2DC;min-height:34px;
}
div[data-baseweb="select"] svg{fill:var(--dim);}

[data-testid="stFileUploaderDropzone"]{
  background:rgba(255,255,255,.018);border:1px dashed rgba(232,240,236,.16);
  border-radius:14px;padding:22px;
}
[data-testid="stFileUploaderDropzone"]:hover{border-color:rgba(226,96,61,.4);}
[data-testid="stFileUploaderDropzone"] span,[data-testid="stFileUploaderDropzone"] small{color:var(--muted);font-family:var(--sans);}

.stTabs [data-baseweb="tab-list"]{gap:20px;border-bottom:1px solid var(--line);}
.stTabs [data-baseweb="tab"]{
  background:transparent;padding:11px 1px;font:500 10.5px/1 var(--mono);
  letter-spacing:.13em;text-transform:uppercase;color:var(--dim);
}
.stTabs [aria-selected="true"]{color:#F2F6F3;}
.stTabs [data-baseweb="tab-highlight"]{background:var(--oxide);height:2px;}
.stTabs [data-baseweb="tab-border"]{display:none;}

[data-testid="stCode"] pre, pre{background:#0B1110 !important;border:1px solid var(--line) !important;border-radius:10px !important;}
[data-testid="stCode"] code{font:400 11.5px/1.65 var(--mono) !important;color:#D3DED8 !important;}
.stDownloadButton button{
  background:rgba(255,255,255,.028);border:1px solid var(--line);color:var(--muted);
  border-radius:9px;font:500 11.5px/1 var(--sans);
}
.stDownloadButton button:hover{border-color:rgba(226,96,61,.45);color:#F4F8F5;}
hr{border-color:var(--line);}
div[data-testid="stVerticalBlockBorderWrapper"]{border-radius:13px;}

/* ---------------- preflight console ---------------- */
.console{border:1px solid var(--line);border-radius:15px;background:#0D1312;overflow:hidden;margin-top:6px;}
.console-head{padding:20px 24px 16px;border-bottom:1px solid var(--line-soft);display:flex;align-items:flex-end;gap:14px;flex-wrap:wrap;}
.console-head h3{font:400 17px/1.3 var(--serif);color:#E4EBE6;margin:9px 0 0;flex:1 1 340px;}
.console-hint{font:400 10px/1 var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--dim);}
.console-grid{display:grid;grid-template-columns:1.05fr .95fr;gap:0;}
.console-col{padding:18px 22px 22px;}
.console-col + .console-col{border-left:1px solid var(--line-soft);}
.mock-card{border:1px solid var(--line);border-radius:10px;padding:11px 13px;margin-bottom:8px;background:rgba(255,255,255,.02);}
.mock-card.soft{opacity:.72;}
.mock-detail{border:1px solid var(--line);border-radius:10px;padding:14px;background:rgba(255,255,255,.018);}
.mock-tabs{display:flex;gap:14px;border-bottom:1px solid var(--line-soft);padding-bottom:9px;margin-bottom:11px;}
.mock-tabs span{font:500 9px/1 var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--dim);}
.mock-tabs span.on{color:#DCE5DF;border-bottom:1px solid var(--oxide);padding-bottom:9px;margin-bottom:-10px;}
.mock-line{height:6px;border-radius:3px;background:rgba(232,240,236,.075);margin-bottom:7px;}
@media (max-width:1100px){
  .console-grid{grid-template-columns:1fr;}
  .console-col + .console-col{border-left:none;border-top:1px solid var(--line-soft);}
}
</style>
"""

st.markdown(CSS, unsafe_allow_html=True)

esc = html.escape


# --------------------------------------------------------------------------- #
# State
# --------------------------------------------------------------------------- #

ss = st.session_state
ss.setdefault("text", "")
ss.setdefault("name", "")
ss.setdefault("fmt", "auto")
ss.setdefault("lens", "errors")
ss.setdefault("mask", True)
ss.setdefault("sel", None)
ss.setdefault("upload_epoch", 0)


def load_log(text: str, name: str) -> None:
    ss.text = text
    ss.name = name
    ss.sel = None
    ss.lens = "errors"


# Optional demo boot: `ATLAS_DEMO=1 streamlit run app.py` opens the sample case file.
if os.environ.get("ATLAS_DEMO") == "1" and not ss.text:
    try:
        with open(SAMPLE_PATH, "r", encoding="utf-8") as _handle:
            load_log(_handle.read(), "safe-example.log")
    except OSError:
        pass


@st.cache_data(show_spinner=False)
def analyse(text: str, fmt: str):
    records, detected, confidence = ap.parse_log(text, fmt)
    return records, detected, confidence


def read_upload(file) -> tuple[str, str]:
    raw = file.getvalue()
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return raw.decode(encoding), file.name
        except Exception:
            continue
    return raw.decode("utf-8", errors="replace"), file.name


# --------------------------------------------------------------------------- #
# Render helpers
# --------------------------------------------------------------------------- #

SEV_CLASS = {"ERROR": "ERROR", "WARN": "WARN", "INFO": "INFO"}


def badge(severity: str) -> str:
    return f'<span class="badge {SEV_CLASS.get(severity, "OTHER")}">{esc(severity)}</span>'


def truncate(value: str, limit: int = 156) -> str:
    value = value.strip()
    return value if len(value) <= limit else value[:limit].rstrip() + "…"


def display(value: str) -> str:
    return ap.mask_text(value) if ss.mask else value


def display_fact(key: str, value: str) -> str:
    return ap.mask_fact(key, value) if ss.mask else value


def incident_card_html(incident: ap.Incident) -> str:
    record = incident.first
    tag = '<span class="tag">TRANSACTION</span>' if incident.is_transaction else ""
    exc = record.exceptions[0].split(".")[-1] if record.exceptions else ""
    exc_html = f'<span class="exc">{esc(exc)}</span>' if exc else ""
    return (
        '<div class="card-top">'
        f"{badge(incident.severity)}"
        f'<span class="mono-time">{esc(ap.human_time(incident.latest))}</span>'
        f"{tag}"
        f'<span class="count">×{incident.count}</span>'
        "</div>"
        f'<div class="card-title">{esc(truncate(display(incident.title)))}</div>'
        '<div class="card-foot">'
        f"<span>{esc(incident.component)}</span>{exc_html}"
        "</div>"
    )


def signal_card_html(record: ap.Record) -> str:
    return (
        '<div class="card-top">'
        f"{badge(record.severity)}"
        f'<span class="mono-time">{esc(ap.human_time(record.timestamp))}</span>'
        '<span class="count">OK</span>'
        "</div>"
        f'<div class="card-title">{esc(truncate(display(record.header)))}</div>'
        '<div class="card-foot">'
        f"<span>{esc(record.component)}</span>"
        '<span class="ok">healthy signal</span>'
        "</div>"
    )


def meta_row(label: str, value: str) -> str:
    return f"<div><dt>{esc(label)}</dt><dd>{esc(value)}</dd></div>"


def fact_row(key: str, value: str) -> str:
    return f"<div><dt>{esc(key)}</dt><dd>{esc(display_fact(key, value))}</dd></div>"


def widget_key(prefix: str, raw: str) -> str:
    """Stable, DOM-safe widget key (record ids contain | : and spaces)."""
    return f"{prefix}-{hashlib.sha1(raw.encode('utf-8')).hexdigest()[:10]}"



# --------------------------------------------------------------------------- #
# Sidebar
# --------------------------------------------------------------------------- #

records, fmt, confidence = ([], "generic", "Fallback")
incidents: list[ap.Incident] = []
if ss.text:
    records, fmt, confidence = analyse(ss.text, ss.fmt)
    incidents = ap.build_incidents(records)

stats = ap.summarise(records)
error_count = stats["errors"]
warn_count = stats["warnings"]
tx_records = [r for r in records if r.is_transaction]
healthy = [r for r in records if r.is_success]

LENSES = [
    ("errors", "Errors & warnings", len(incidents)),
    ("transactions", "Transactions", sum(1 for i in incidents if i.is_transaction)),
    ("operations", "Operational signals", len(healthy)),
    ("all", "All grouped cases", len(incidents)),
]

with st.sidebar:
    st.markdown(
        '<div class="brand"><div class="mark"></div><div>'
        "<b>Diagnostic Atlas</b><span>log triage workspace</span></div></div>",
        unsafe_allow_html=True,
    )

    uploaded = st.file_uploader(
        "Log file",
        type=["log", "txt", "json", "jsonl", "out", "trace", "csv"],
        label_visibility="collapsed",
        key=f"side_upload_{ss.upload_epoch}",
    )
    if uploaded is not None:
        signature = f"{uploaded.name}:{uploaded.size}"
        if ss.get("sig") != signature:
            text, name = read_upload(uploaded)
            load_log(text, name)
            ss["sig"] = signature
            st.rerun()

    if ss.text:
        st.markdown('<div class="sidebar-rule"></div>', unsafe_allow_html=True)
        st.markdown('<span class="rail-label">Investigation lens</span>', unsafe_allow_html=True)
        for lens_id, label, count in LENSES:
            active = ss.lens == lens_id
            marker = "●" if active else "○"
            if st.button(
                f"{marker}  {label} · {count}",
                key=f"lens-{lens_id}",
                use_container_width=True,
            ):
                ss.lens = lens_id
                ss.sel = None
                st.rerun()

        active_selector = f'div[class*="st-key-lens-{ss.lens}"] button'
        st.markdown(
            "<style>"
            f"{active_selector}{{background:rgba(226,96,61,.11);border-color:rgba(226,96,61,.34);color:#F4F8F5;}}"
            f"{active_selector} p{{color:#F4F8F5;font-weight:600;}}"
            "</style>",
            unsafe_allow_html=True,
        )

        if st.button("Clear workspace", use_container_width=True, key="clear"):
            load_log("", "")
            ss["sig"] = None
            # Bump the uploader key so the file that is still attached to the old
            # widget does not immediately reload itself.
            ss.upload_epoch = ss.get("upload_epoch", 0) + 1
            st.rerun()

    st.markdown(
        '<div class="privacy"><div class="stamp">● Local parsing</div>'
        "<p>Your file is parsed inside this Python process and never uploaded to a "
        "third party. Masking is applied before anything is displayed.</p></div>",
        unsafe_allow_html=True,
    )


# --------------------------------------------------------------------------- #
# Empty state
# --------------------------------------------------------------------------- #

if not ss.text:
    st.markdown(
        '<div class="hero"><span class="eyebrow">Grouped by incident</span>'
        "<h2>Turn a wall of trace text into a clear case file.</h2>"
        "<p>Vista, JSON, bracketed application, syslog, and common timestamped logs are "
        "grouped into readable incident cases. Multiline stack traces stay attached to the "
        "header that caused them.</p></div>",
        unsafe_allow_html=True,
    )

    st.write("")
    left, right = st.columns([1.55, 1], gap="large")
    with left:
        hero_upload = st.file_uploader(
            "Drop a .log, .txt or .json file here",
            type=["log", "txt", "json", "jsonl", "out", "trace", "csv"],
            key="hero_upload",
        )
        if hero_upload is not None:
            text, name = read_upload(hero_upload)
            load_log(text, name)
            st.rerun()
        st.markdown(
            '<div class="subline" style="margin-top:8px;">Auto-detect supports Vista, JSON, '
            "bracketed application, syslog, and timestamped logs.</div>",
            unsafe_allow_html=True,
        )
    with right:
        st.markdown(
            '<span class="rail-label">No file at hand?</span>'
            '<div class="subline" style="margin-bottom:10px;">Load a synthetic Vista log with '
            "two failures, one warning and two healthy signals.</div>",
            unsafe_allow_html=True,
        )
        if st.button("Explore a safe example", use_container_width=True, key="sample"):
            with open(SAMPLE_PATH, "r", encoding="utf-8") as handle:
                load_log(handle.read(), "safe-example.log")
            st.rerun()

    st.markdown(
        '<section class="console">'
        '<div class="console-head"><div style="flex:1 1 340px;">'
        '<span class="eyebrow">Workspace preview</span>'
        "<h3>The investigation structure is ready before the file arrives.</h3></div>"
        '<span class="console-hint">header → detail</span></div>'
        '<div class="console-grid">'
        '<div class="console-col"><span class="rail-label">Grouped incident stream</span>'
        '<div class="mock-card"><div class="card-top"><span class="badge ERROR">ERROR</span>'
        '<span class="mono-time">00:20:04</span><span class="count">× 46</span></div>'
        '<div class="card-title">Send mail failed. See exception stack trace for details.</div>'
        '<div class="card-foot"><span>OnlineStoreEmailService</span>'
        '<span class="exc">SmtpException</span></div></div>'
        '<div class="mock-card"><div class="card-top"><span class="badge ERROR">ERROR</span>'
        '<span class="mono-time">03:11:16</span><span class="tag">TRANSACTION</span>'
        '<span class="count">× 1</span></div>'
        '<div class="card-title">Order completion failed after payment confirmation.</div>'
        '<div class="card-foot"><span>WSVistaWebClient</span>'
        '<span class="exc">VSS response code 55</span></div></div>'
        '<div class="mock-card soft"><div class="card-top"><span class="badge WARN">WARN</span>'
        '<span class="mono-time">02:43:43</span><span class="count">× 2</span></div>'
        '<div class="card-title">Loyalty recognition discount values cannot sum to zero.</div>'
        '<div class="card-foot"><span>ApplyLoyaltyRecognitionDiscounts</span></div></div>'
        '<div class="mock-card soft"><div class="card-top"><span class="badge INFO">INFO</span>'
        '<span class="mono-time">03:00:57</span><span class="count">OK</span></div>'
        '<div class="card-title">WSVistaWebClient started</div>'
        '<div class="card-foot"><span>WSVistaWebClient</span>'
        '<span class="ok">healthy signal</span></div></div>'
        "</div>"
        '<div class="console-col"><span class="rail-label">Case-file detail</span>'
        '<div class="mock-detail">'
        '<div class="mock-tabs"><span class="on">Overview</span><span>Transaction</span>'
        "<span>Raw detail</span></div>"
        '<div class="mock-line" style="width:62%"></div>'
        '<div class="mock-line" style="width:88%"></div>'
        '<div class="mock-line" style="width:44%;margin-bottom:14px"></div>'
        '<div class="mock-line" style="width:74%"></div>'
        '<div class="mock-line" style="width:81%"></div>'
        '<div class="mock-line" style="width:57%;margin-bottom:0"></div>'
        "</div></div></div></section>",
        unsafe_allow_html=True,
    )
    st.stop()


# --------------------------------------------------------------------------- #
# Workspace
# --------------------------------------------------------------------------- #

visible_incidents = list(incidents)
if ss.lens == "transactions":
    visible_incidents = [i for i in incidents if i.is_transaction]

query = ""
visible_records = healthy if ss.lens == "operations" else []

st.write("")
head_left, head_right = st.columns([1.5, 1], gap="large")

with head_left:
    st.markdown(
        '<span class="eyebrow">Diagnostic Atlas · case workspace</span>'
        f'<div class="atlas-title">{esc(ss.name or "Triage the failure, keep the context.")}</div>'
        f'<div class="subline">{len(records)} records · <b>{ap.FORMAT_LABELS.get(fmt, fmt)}</b>'
        f" · {confidence.lower()} confidence · {error_count} errors</div>",
        unsafe_allow_html=True,
    )

with head_right:
    c1, c2, c3 = st.columns([1.35, 1, 1], gap="small")
    with c1:
        fmt_choice = st.selectbox(
            "Format",
            options=[f[0] for f in ap.FORMATS],
            index=[f[0] for f in ap.FORMATS].index(ss.fmt),
            format_func=lambda key: ap.FORMAT_LABELS[key],
            label_visibility="collapsed",
            key="fmt_select",
        )
        if fmt_choice != ss.fmt:
            ss.fmt = fmt_choice
            st.rerun()
    with c2:
        ss.mask = st.toggle(
            "Mask",
            value=ss.mask,
            key="mask_toggle",
            help="Mask identifiers, hosts and correlation IDs",
        )
    with c3:
        export = {
            "tool": "Diagnostic Atlas",
            "file": ss.name,
            "format": fmt,
            "confidence": confidence,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "stats": stats,
            "incidents": [
                {
                    "severity": inc.severity,
                    "component": inc.component,
                    "title": display(inc.title),
                    "count": inc.count,
                    "latest": inc.latest,
                    "is_transaction": inc.is_transaction,
                    "records": [
                        {
                            "timestamp": rec.timestamp,
                            "severity": rec.severity,
                            "component": rec.component,
                            "header": display(rec.header),
                            "facts": {k: display_fact(k, v) for k, v in rec.facts.items()},
                            "exceptions": rec.exceptions,
                            "raw": display(rec.raw),
                        }
                        for rec in inc.records
                    ],
                }
                for inc in incidents
            ],
        }
        st.download_button(
            "Export view",
            data=json.dumps(export, indent=2, ensure_ascii=False),
            file_name="diagnostic-atlas-case-file.json",
            mime="application/json",
            use_container_width=True,
            key="export",
        )

st.markdown(
    '<div class="stats" style="margin-top:16px;">'
    f'<div class="stat"><b>{len(records)}</b><span>records</span></div>'
    f'<div class="stat"><b>{error_count}</b><span>errors</span></div>'
    f'<div class="stat"><b>{warn_count}</b><span>warnings</span></div>'
    f'<div class="stat"><b>{len(incidents)}</b><span>incident patterns</span></div>'
    f'<div class="stat"><b>{len(tx_records)}</b><span>transaction records</span></div>'
    f'<div class="stat"><b>{len(healthy)}</b><span>healthy signals</span></div>'
    "</div>",
    unsafe_allow_html=True,
)

st.write("")
stream_col, case_col = st.columns([1.02, 0.98], gap="large")

# ------------------------------- stream ------------------------------------ #

with stream_col:
    st.markdown('<span class="rail-label">Grouped incident stream</span>', unsafe_allow_html=True)
    search = st.text_input(
        "Search",
        placeholder="Search error, component, booking…",
        label_visibility="collapsed",
        key="search",
    )
    needle = search.strip().lower()

    if ss.lens == "operations":
        visible_records = [
            r for r in healthy
            if not needle or needle in f"{r.header} {r.component} {r.raw}".lower()
        ]
        st.markdown(
            f'<div class="stream-count" style="margin:2px 0 10px;">{len(visible_records)} visible</div>',
            unsafe_allow_html=True,
        )
        if not visible_records:
            st.markdown('<p class="quiet">No operational signals match this filter.</p>', unsafe_allow_html=True)
        for idx, rec in enumerate(visible_records):
            selected = ss.sel == rec.id
            key = f"card-sel-{idx}" if selected else f"card-{idx}"
            with st.container(key=key):
                body, action = st.columns([0.78, 0.22], gap="small")
                with body:
                    st.markdown(signal_card_html(rec), unsafe_allow_html=True)
                with action:
                    if st.button("Open", key=widget_key("open", rec.id), use_container_width=True):
                        ss.sel = rec.id
                        st.rerun()
    else:
        if needle:
            visible_incidents = [
                inc for inc in visible_incidents
                if needle in f"{inc.title} {inc.component} {' '.join(r.raw for r in inc.records)}".lower()
            ]
        st.markdown(
            f'<div class="stream-count" style="margin:2px 0 10px;">{len(visible_incidents)} visible</div>',
            unsafe_allow_html=True,
        )
        if not visible_incidents:
            st.markdown(
                '<p class="quiet">Nothing in this lens matches the search. Try “all grouped cases”.</p>',
                unsafe_allow_html=True,
            )
        for idx, inc in enumerate(visible_incidents):
            selected = ss.sel in {r.id for r in inc.records}
            key = f"card-sel-{idx}" if selected else f"card-{idx}"
            with st.container(key=key):
                body, action = st.columns([0.78, 0.22], gap="small")
                with body:
                    st.markdown(incident_card_html(inc), unsafe_allow_html=True)
                with action:
                    if st.button("Open", key=widget_key("open", f"{idx}-{inc.id}"), use_container_width=True):
                        ss.sel = inc.first.id
                        st.rerun()

# ------------------------------- case file --------------------------------- #

selected_record = next((r for r in records if r.id == ss.sel), None)
if selected_record is None:
    if ss.lens == "operations" and visible_records:
        selected_record = visible_records[0]
    elif visible_incidents:
        selected_record = visible_incidents[0].first
    elif records:
        selected_record = records[0]

with case_col:
    st.markdown('<span class="rail-label">Case-file detail</span>', unsafe_allow_html=True)
    if selected_record is None:
        st.markdown('<p class="quiet">Select a case to inspect it.</p>', unsafe_allow_html=True)
    else:
        rec = selected_record
        flags = badge(rec.severity) + (
            '<span class="tag">TRANSACTION</span>' if rec.is_transaction else ""
        )
        st.markdown(
            '<div class="case-head">'
            f'<div class="case-flags">{flags}</div>'
            f"<h3>{esc(display(rec.header))}</h3>"
            '<div class="case-stamps">'
            f"<span>{esc(ap.human_time(rec.timestamp))}</span>"
            f"<span>{esc(rec.component)}</span>"
            f"<span>{esc(rec.fmt)}</span>"
            "</div></div>",
            unsafe_allow_html=True,
        )

        has_facts = bool(rec.facts) or rec.is_transaction
        tab_overview, tab_tx, tab_raw = st.tabs(
            ["Overview", f"Transaction ({len(rec.facts)})" if has_facts else "Transaction", "Raw detail"]
        )

        with tab_overview:
            st.markdown(
                '<div style="height:14px"></div>'
                '<span class="section-label">Error header</span>'
                f'<p class="header-summary">{esc(display(rec.header))}</p>',
                unsafe_allow_html=True,
            )
            st.markdown(
                '<div style="height:18px"></div>'
                '<span class="section-label">Event context</span>'
                '<dl class="meta-grid">'
                + meta_row("Component", rec.component)
                + meta_row("Correlation ID", display(rec.correlation_id) or "—")
                + meta_row("Version", rec.version or "—")
                + meta_row(
                    "Details",
                    f"{rec.attached_lines} attached lines" if rec.details else "Header only",
                )
                + "</dl>",
                unsafe_allow_html=True,
            )

            if rec.exceptions:
                items = "".join(
                    f"<div><span>{i + 1}</span><code>{esc(name)}</code></div>"
                    for i, name in enumerate(rec.exceptions)
                )
                st.markdown(
                    '<div style="height:18px"></div>'
                    '<span class="section-label">Exception chain</span>'
                    f'<div class="exc-list">{items}</div>',
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    '<div style="height:18px"></div>'
                    '<span class="section-label">Exception chain</span>'
                    '<p class="quiet">No .NET exception class was extracted from this record.</p>',
                    unsafe_allow_html=True,
                )

        with tab_tx:
            st.markdown('<div style="height:14px"></div>', unsafe_allow_html=True)
            if rec.is_transaction:
                st.markdown(
                    '<div class="callout"><div class="dot"></div><div>'
                    "<strong>Transaction evidence detected</strong>"
                    "<p>Fields were detected from the header and its attached detail lines.</p>"
                    "</div></div>",
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    '<div class="callout muted"><div class="dot"></div><div>'
                    "<strong>No transaction markers in this record</strong>"
                    "<p>This tab becomes useful for entries containing order, payment, booking, "
                    "or transaction fields.</p></div></div>",
                    unsafe_allow_html=True,
                )
            if rec.facts:
                rows = "".join(fact_row(k, v) for k, v in rec.facts.items())
                st.markdown(f'<dl class="facts">{rows}</dl>', unsafe_allow_html=True)
            elif rec.is_transaction:
                st.markdown(
                    '<dl class="facts"><div><dt>Detected context</dt>'
                    "<dd>Order/payment terminology is present, but no standardized transaction "
                    "field was found.</dd></div></dl>",
                    unsafe_allow_html=True,
                )

        with tab_raw:
            st.markdown(
                '<div style="height:14px"></div>'
                '<span class="section-label">Preserved multiline evidence</span>',
                unsafe_allow_html=True,
            )
            st.code(display(rec.raw), language="text")
