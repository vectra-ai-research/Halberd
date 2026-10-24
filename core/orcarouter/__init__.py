"""First-class OrcaRouter Cyber Inference provider for Halberd.

The package is intentionally free of third-party imports so that the provider,
credential and model-catalog layers can be unit tested without the full
Halberd dependency tree.
"""

from .config import PROVIDER_ID, PROVIDER_LABEL, resolve_origins

__all__ = ["PROVIDER_ID", "PROVIDER_LABEL", "resolve_origins"]
