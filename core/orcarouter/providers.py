"""Provider registry.

Halberd previously hardcoded a single Anthropic client. The registry makes the
provider a first-class choice while leaving the existing provider untouched.
"""

from __future__ import annotations

from dataclasses import dataclass

from .config import (
    DEFAULT_MODEL,
    ENV_API_KEY,
    PROVIDER_CYBER_MODELS,
    PROVIDER_CYBER_PAGE,
    PROVIDER_HOME,
    PROVIDER_ID,
    PROVIDER_LABEL,
)


@dataclass(frozen=True)
class ProviderSpec:
    id: str
    label: str
    env_key: str
    default_model: str | None = None
    supports_oauth: bool = False
    docs_url: str = ""


ANTHROPIC = ProviderSpec(
    id="anthropic",
    label="Anthropic Claude",
    env_key="ANTHROPIC_API_KEY",
    default_model=None,
)

ORCAROUTER = ProviderSpec(
    id=PROVIDER_ID,
    label=PROVIDER_LABEL,
    env_key=ENV_API_KEY,
    default_model=DEFAULT_MODEL,
    supports_oauth=True,
    docs_url=PROVIDER_CYBER_PAGE,
)

PROVIDERS: tuple[ProviderSpec, ...] = (ANTHROPIC, ORCAROUTER)

_BY_ID = {spec.id: spec for spec in PROVIDERS}


def get_provider(provider_id: str | None) -> ProviderSpec:
    return _BY_ID.get((provider_id or "").strip(), ANTHROPIC)


def provider_options() -> list[dict]:
    return [{"label": spec.label, "value": spec.id} for spec in PROVIDERS]


def links() -> dict:
    return {
        "home": PROVIDER_HOME,
        "cyber_page": PROVIDER_CYBER_PAGE,
        "cyber_models": PROVIDER_CYBER_MODELS,
    }
