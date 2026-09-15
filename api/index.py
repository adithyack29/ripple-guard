"""Vercel Python Functions entrypoint.

Re-exports the existing FastAPI app (backend/app/main.py) unmodified —
this file is deployment plumbing only, not application logic. Vercel's
Python runtime detects the ASGI app via the module-level `app` name.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.main import app  # noqa: E402
