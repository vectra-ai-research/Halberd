"""Test bootstrap.

Halberd's loggers are configured at import time and open ``local/app.log``
directly, and the app's own ``Bootstrapper`` is what normally creates that
directory. A fresh checkout has no ``local/`` (it is ignored), so create it
before any test module imports the agent or the Dash app.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

for _directory in ("local", "local/chats", "output", "report"):
    (ROOT / _directory).mkdir(parents=True, exist_ok=True)
