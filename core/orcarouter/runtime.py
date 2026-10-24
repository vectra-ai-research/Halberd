"""Shared OrcaRouter runtime objects.

One credential store, one catalog cache and one authorization manager per
process, so the settings panel, the chat page and the agent all observe the
same state.
"""

from __future__ import annotations

import threading

from .catalog import CatalogResult, CatalogService
from .client import OrcaRouterClient
from .config import DEFAULT_MODEL, resolve_origins
from .credentials import OrcaCredential, get_credential_store
from .pkce import OrcaAuthManager
from .settings import get_agent_settings

_LOCK = threading.RLock()
_CATALOG: CatalogService | None = None
_AUTH: OrcaAuthManager | None = None
_ORIGINS = None


def origins():
    global _ORIGINS
    with _LOCK:
        if _ORIGINS is None:
            _ORIGINS = resolve_origins()
        return _ORIGINS


def reset_runtime() -> None:
    """Re-read origin overrides (used after settings changes and in tests)."""
    global _ORIGINS, _CATALOG, _AUTH
    with _LOCK:
        _ORIGINS = resolve_origins()
        if _CATALOG is not None:
            _CATALOG.set_api_base(_ORIGINS.api_base)
        _AUTH = None


def credential_store():
    return get_credential_store()


def catalog_service() -> CatalogService:
    global _CATALOG
    with _LOCK:
        if _CATALOG is None:
            _CATALOG = CatalogService(origins().api_base)
        return _CATALOG


def auth_manager() -> OrcaAuthManager:
    global _AUTH
    with _LOCK:
        if _AUTH is None:
            _AUTH = OrcaAuthManager(get_credential_store(), origins())
        return _AUTH


def current_credential() -> OrcaCredential | None:
    return get_credential_store().load()


def current_api_key() -> str:
    credential = current_credential()
    return credential.api_key if credential else ""


def client(api_key: str | None = None, timeout: float = 120.0) -> OrcaRouterClient:
    return OrcaRouterClient(origins().api_base, api_key or current_api_key(), timeout=timeout)


def model_catalog(
    capability: str = "chat",
    modalities=(),
    refresh: bool = False,
    force_seed: bool = False,
    api_key: str | None = None,
) -> CatalogResult:
    key = api_key if api_key is not None else current_api_key()
    return catalog_service().result(
        capability=capability,
        modalities=modalities,
        api_key=key,
        refresh=refresh,
        force_seed=force_seed,
    )


def current_model() -> str:
    model = get_agent_settings().model()
    return model or DEFAULT_MODEL
