"""Launcher for Diagnostic Atlas.

Streamlit's server (uvicorn + anyio) can hit a CPython/Windows crash inside
`asyncio.proactor_events._write_to_self` when the script-runner thread calls
back into a ProactorEventLoop. Switching the process to the selector-based
event loop policy avoids it and changes nothing else.

Use:
    python run.py            # http://127.0.0.1:8501
"""

import asyncio
import sys


def main() -> None:
    if sys.platform == "win32":
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except AttributeError:  # pragma: no cover - non-Windows
            pass

    from streamlit.web import cli as stcli

    sys.argv = ["streamlit", "run", "app.py", *sys.argv[1:]]
    sys.exit(stcli.main())


if __name__ == "__main__":
    main()
