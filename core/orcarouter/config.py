"""Configuration for the OrcaRouter Cyber Inference provider.

OrcaRouter uses two public origins:

* authentication and code exchange: ``https://www.orcarouter.ai``
* inference and model discovery:     ``https://api.orcarouter.ai/v1``

One origin must never be derived from the other by rewriting a hostname or by
blindly appending ``/v1``. Self-hosted deployments may share a single origin,
so ``ORCA_BASE_URL`` acts as a fallback and the explicit
``ORCA_AUTH_BASE_URL`` / ``ORCA_API_BASE_URL`` values take precedence.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

PROVIDER_ID = "orcarouter"
PROVIDER_LABEL = "OrcaRouter Cyber Inference"
PROVIDER_HOME = "https://www.orcarouter.ai"
PROVIDER_CYBER_PAGE = "https://www.orcarouter.ai/cyber"
PROVIDER_CYBER_MODELS = "https://www.orcarouter.ai/models?tier=cyber"
PROVIDER_KEY_PAGE = "https://www.orcarouter.ai/console/keys"
PROVIDER_AUTHORIZED_APPS = "https://www.orcarouter.ai/console/authorized-apps"

DEFAULT_AUTH_BASE = "https://www.orcarouter.ai"
DEFAULT_API_BASE = "https://api.orcarouter.ai/v1"

AUTHORIZE_PATH = "/auth"
# The relay lives on api.orcarouter.ai at /v1; authentication does not.
# https://api.orcarouter.ai/v1/auth/keys is a 404.
EXCHANGE_PATH = "/api/v1/auth/keys"

APP_NAME = "Halberd"
DEFAULT_SCOPE = "api"
SUPPORTED_SCOPES = ("api", "connector")

#: ``orcarouter/auto`` is the provider default: automatic routing, usable with
#: any key. ``orcarouter/fusion`` is the general fallback.
DEFAULT_MODEL = "orcarouter/auto"
FALLBACK_MODEL = "orcarouter/fusion"

#: Dedicated cyber models (vendor namespace preserved as returned by the live
#: catalog). They are recommended for security teams, not hardcoded defaults.
CYBER_MODELS = ("orca/orcacyber-ultra-1.0", "orca/orcacyber-zero-1.5")

ENV_API_KEY = "ORCAROUTER_API_KEY"
ENV_SHARED_BASE = "ORCA_BASE_URL"
ENV_AUTH_BASE = "ORCA_AUTH_BASE_URL"
ENV_API_BASE = "ORCA_API_BASE_URL"

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


class ConfigError(ValueError):
    """Raised when an origin override violates the transport policy."""


@dataclass(frozen=True)
class Origins:
    auth_base: str
    api_base: str


def _normalise_base(value: str) -> str:
    return value.strip().rstrip("/")


def _is_loopback(hostname: str | None) -> bool:
    return bool(hostname) and hostname.lower() in LOOPBACK_HOSTS


def _check_transport(url: str, label: str) -> None:
    parts = urlsplit(url)
    if not parts.scheme or not parts.hostname:
        raise ConfigError(f"{label} must be an absolute URL, got {url!r}")
    if parts.scheme == "https":
        return
    if parts.scheme == "http" and _is_loopback(parts.hostname):
        return
    raise ConfigError(
        f"{label} must use HTTPS (HTTP is allowed only for loopback), got {url!r}"
    )


def _append_api_prefix(url: str) -> str:
    """Give an override that carries no path the documented ``/v1`` prefix.

    A value supplied with a path is used verbatim: the override is the complete
    API base URL, so a self-hosted deployment on ``/gateway/openai`` is not
    silently rewritten.
    """
    parts = urlsplit(url)
    if parts.path in ("", "/"):
        return urlunsplit((parts.scheme, parts.netloc, "/v1", parts.query, ""))
    return url


def resolve_origins(environ: dict | None = None) -> Origins:
    env = os.environ if environ is None else environ
    shared = _normalise_base(env.get(ENV_SHARED_BASE) or "")
    explicit_auth = _normalise_base(env.get(ENV_AUTH_BASE) or "")
    explicit_api = _normalise_base(env.get(ENV_API_BASE) or "")

    auth_base = explicit_auth or shared or DEFAULT_AUTH_BASE
    if explicit_api:
        api_base = _append_api_prefix(explicit_api)
    elif shared:
        api_base = _append_api_prefix(shared)
    else:
        api_base = DEFAULT_API_BASE

    _check_transport(auth_base, "OrcaRouter auth base URL")
    _check_transport(api_base, "OrcaRouter API base URL")
    return Origins(auth_base=auth_base, api_base=api_base)


def authorize_url(origins: Origins) -> str:
    return origins.auth_base.rstrip("/") + AUTHORIZE_PATH


def exchange_url(origins: Origins) -> str:
    return origins.auth_base.rstrip("/") + EXCHANGE_PATH
