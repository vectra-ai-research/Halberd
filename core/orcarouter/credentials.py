"""Credential seam for OrcaRouter.

Two acquisition adapters feed one interface:

* ``save_api_key`` — the user pastes an existing ``sk-orca-…`` key;
* ``save_pkce_credential`` — the OAuth 2.0 + PKCE connect flow returns a key.

Both produce the same :class:`OrcaCredential`. The provider, the model catalog
and every chat entry point consume that object and never care which adapter
produced it.

Secrets live in the project's existing ``.env`` file (the same file the
Anthropic key already uses) and in ``os.environ`` for the running process. No
new secret store is introduced.
"""

from __future__ import annotations

import os
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .config import ENV_API_KEY, SUPPORTED_SCOPES
from .envfile import read_env_file, write_env_values

ENV_SOURCE = "ORCAROUTER_CREDENTIAL_SOURCE"
ENV_ACCOUNT = "ORCAROUTER_ACCOUNT_ID"
ENV_SCOPE = "ORCAROUTER_GRANTED_SCOPE"

SOURCE_API_KEY = "api_key"
SOURCE_PKCE = "pkce"
SOURCE_ENV = "env"
VALID_SOURCES = (SOURCE_API_KEY, SOURCE_PKCE, SOURCE_ENV)

_KEY_PATTERN = re.compile(r"sk-[A-Za-z0-9_\-]{6,}")
_SAFE_TAIL = 4


class CredentialError(Exception):
    """A credential could not be accepted or used."""


@dataclass(frozen=True)
class OrcaCredential:
    api_key: str
    source: str
    account_id: str | None = None
    scope: str = "api"
    generation: int = 0

    @property
    def masked(self) -> str:
        return mask_key(self.api_key)

    def __repr__(self) -> str:  # never expose the secret in logs or tracebacks
        return (
            f"OrcaCredential(source={self.source!r}, account_id={self.account_id!r}, "
            f"scope={self.scope!r}, generation={self.generation}, key={self.masked})"
        )


def mask_key(key: str | None) -> str:
    """Return a display-safe rendering of a key."""
    if not key:
        return ""
    if len(key) <= _SAFE_TAIL:
        return "…"
    prefix = "sk-orca-…" if key.startswith("sk-orca-") else "…"
    return prefix + key[-_SAFE_TAIL:]


def redact(text: str, *extra_secrets: str) -> str:
    """Strip any credential material out of a message before it is shown."""
    if not text:
        return text
    cleaned = str(text)
    for secret in extra_secrets:
        if secret and len(secret) >= 6:
            cleaned = cleaned.replace(secret, mask_key(secret))
    return _KEY_PATTERN.sub(lambda m: mask_key(m.group(0)), cleaned)


def _validate_key(key: str) -> str:
    candidate = (key or "").strip()
    if not candidate:
        raise CredentialError("Enter an OrcaRouter API key.")
    if any(ch.isspace() for ch in candidate):
        raise CredentialError("An OrcaRouter API key cannot contain whitespace.")
    if len(candidate) < 12:
        raise CredentialError("That key is too short to be an OrcaRouter API key.")
    return candidate


def _parse_env_file(path: Path) -> list[tuple[str, str, str]]:
    return read_env_file(path)


class CredentialStore:
    """Thread-safe credential store backed by ``.env`` + ``os.environ``."""

    def __init__(self, env_path: str | os.PathLike | None = None, environ=None):
        self._path = Path(env_path) if env_path is not None else Path(".env")
        self._environ = os.environ if environ is None else environ
        self._lock = threading.RLock()
        self._generation = 1
        self._needs_reauth_account: str | None = None
        self._needs_reauth_generation: int | None = None

    # ------------------------------------------------------------------ read
    def _file_values(self) -> dict[str, str]:
        return {k: v for k, v, _ in _parse_env_file(self._path) if k}

    def load(self) -> OrcaCredential | None:
        with self._lock:
            key = (self._environ.get(ENV_API_KEY) or "").strip()
            values = self._file_values()
            if key:
                source = (self._environ.get(ENV_SOURCE) or "").strip() or SOURCE_ENV
                account = (self._environ.get(ENV_ACCOUNT) or "").strip() or None
                scope = (self._environ.get(ENV_SCOPE) or "").strip() or "api"
            else:
                key = (values.get(ENV_API_KEY) or "").strip()
                if not key:
                    return None
                source = (values.get(ENV_SOURCE) or "").strip() or SOURCE_ENV
                account = (values.get(ENV_ACCOUNT) or "").strip() or None
                scope = (values.get(ENV_SCOPE) or "").strip() or "api"
            if source not in VALID_SOURCES:
                source = SOURCE_ENV
            return OrcaCredential(
                api_key=key,
                source=source,
                account_id=account,
                scope=scope,
                generation=self._generation,
            )

    def generation(self) -> int:
        with self._lock:
            return self._generation

    # ----------------------------------------------------------------- write
    def _persist(self, updates: dict[str, str | None]) -> None:
        """Rewrite the managed keys in ``.env`` atomically, preserving the rest."""
        write_env_values(self._path, updates)

    def _apply(self, credential: OrcaCredential, extra: dict[str, str] | None = None) -> OrcaCredential:
        updates = {
            ENV_API_KEY: credential.api_key,
            ENV_SOURCE: credential.source,
            ENV_ACCOUNT: credential.account_id or None,
            ENV_SCOPE: credential.scope,
        }
        if extra:
            updates.update(extra)
        self._persist(updates)
        self._environ[ENV_API_KEY] = credential.api_key
        self._environ[ENV_SOURCE] = credential.source
        if credential.account_id:
            self._environ[ENV_ACCOUNT] = credential.account_id
        else:
            self._environ.pop(ENV_ACCOUNT, None)
        self._environ[ENV_SCOPE] = credential.scope
        self._generation += 1
        self._needs_reauth_account = None
        self._needs_reauth_generation = None
        return OrcaCredential(
            api_key=credential.api_key,
            source=credential.source,
            account_id=credential.account_id,
            scope=credential.scope,
            generation=self._generation,
        )

    def save_api_key(self, key: str) -> OrcaCredential:
        """Adapter 1: a key the user pasted."""
        candidate = _validate_key(key)
        with self._lock:
            return self._apply(
                OrcaCredential(api_key=candidate, source=SOURCE_API_KEY, account_id=None, scope="api")
            )

    def save_pkce_credential(
        self,
        key: str,
        account_id: str | None,
        granted_scope: str,
        expected_generation: int | None = None,
    ) -> OrcaCredential:
        """Adapter 2: the key minted by the PKCE exchange.

        ``expected_generation`` guards against a late exchange result
        overwriting a credential that was replaced while it was in flight.
        """
        candidate = _validate_key(key)
        scope = (granted_scope or "").strip()
        if scope not in SUPPORTED_SCOPES:
            raise CredentialError(f'Granted scope "{scope}" is not recognised.')
        if scope != "api":
            # Only the api scope permits inference; a connector grant does not.
            raise CredentialError(f'Granted scope "{scope}" does not permit inference.')
        with self._lock:
            if expected_generation is not None and expected_generation != self._generation:
                raise CredentialError("The authorization result is stale; start again.")
            return self._apply(
                OrcaCredential(
                    api_key=candidate,
                    source=SOURCE_PKCE,
                    account_id=(account_id or None),
                    scope=scope,
                )
            )

    def clear(self) -> bool:
        """Remove the stored key from ``.env`` and the running process."""
        with self._lock:
            self._persist({ENV_API_KEY: None, ENV_SOURCE: None, ENV_ACCOUNT: None, ENV_SCOPE: None})
            self._environ.pop(ENV_API_KEY, None)
            self._environ.pop(ENV_SOURCE, None)
            self._environ.pop(ENV_ACCOUNT, None)
            self._environ.pop(ENV_SCOPE, None)
            self._generation += 1
            self._needs_reauth_account = None
            self._needs_reauth_generation = None
            return True

    # ------------------------------------------------------------ 401 handling
    def mark_needs_reauth(self, account_id: str | None, generation: int) -> bool:
        """Terminal ``401`` transition for one exact credential generation.

        A late failure from an old request must never taint a credential that
        has since been replaced. There is no refresh grant: the only recovery
        is a new connect/exchange.
        """
        with self._lock:
            if generation != self._generation:
                return False
            current = self.load()
            if current is None:
                return False
            if account_id and current.account_id and account_id != current.account_id:
                return False
            self._needs_reauth_account = current.account_id or account_id
            self._needs_reauth_generation = generation
            return True

    def needs_reauth(self) -> bool:
        with self._lock:
            return self._needs_reauth_generation == self._generation

    def status(self) -> dict:
        with self._lock:
            credential = self.load()
            return {
                "configured": credential is not None,
                "masked": credential.masked if credential else "",
                "source": credential.source if credential else None,
                "scope": credential.scope if credential else None,
                "account_id": credential.account_id if credential else None,
                "generation": self._generation,
                "needs_reauth": self.needs_reauth(),
            }


_STORE = CredentialStore()


def get_credential_store() -> CredentialStore:
    return _STORE
