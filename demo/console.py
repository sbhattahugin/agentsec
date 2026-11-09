"""One command demo: starts the dummy-agent lab and the AgentSec web console.

    python demo/console.py            # then open http://127.0.0.1:8080
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "demo"))

import lab  # noqa: E402
from agentsec.ui.server import serve  # noqa: E402


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--lab-port", type=int, default=9100, help="First port used by the dummy agents")
    p.add_argument("--no-browser", action="store_true")
    a = p.parse_args()
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    os.environ.setdefault("AGENTSEC_CLIENT_SECRET", "demo-secret")  # secret of the dummy agents only
    print("Starting dummy agents:")
    lab.start(a.lab_port, a.host)
    serve(ROOT / "targets", host=a.host, port=a.port, open_browser=not a.no_browser)


if __name__ == "__main__":
    main()
