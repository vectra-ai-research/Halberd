"""Minimal dotenv read/write helpers shared by the OrcaRouter stores.

Halberd already keeps its provider secrets in the repository-root ``.env``
file; this module reads and rewrites that file without adding a dependency.
"""

from __future__ import annotations

import os
from pathlib import Path

#: Default location, matching the existing Anthropic key handling in halberd.py.
DEFAULT_ENV_PATH = Path(".env")


def read_env_file(path) -> list[tuple[str, str, str]]:
    """Return ``(name, value, original_line)`` triples, preserving order."""
    rows: list[tuple[str, str, str]] = []
    path = Path(path)
    if not path.exists():
        return rows
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            rows.append(("", "", raw))
            continue
        name, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        rows.append((name.strip(), value, raw))
    return rows


def read_env_values(path) -> dict[str, str]:
    return {name: value for name, value, _ in read_env_file(path) if name}


def write_env_values(path, updates: dict[str, str | None]) -> None:
    """Atomically rewrite the given keys, leaving every other line untouched.

    ``None`` deletes the key.
    """
    path = Path(path)
    rows = read_env_file(path)
    managed = set(updates)
    out: list[str] = []
    seen: set[str] = set()
    for name, _value, raw in rows:
        if name in managed:
            if name in seen:
                continue
            seen.add(name)
            value = updates[name]
            if value is None:
                continue
            out.append(f'{name}="{value}"')
        else:
            out.append(raw)
    for name, value in updates.items():
        if name not in seen and value is not None:
            out.append(f'{name}="{value}"')
    body = "\n".join(out).rstrip("\n") + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(body, encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)
