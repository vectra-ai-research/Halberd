"""Live OrcaRouter smoke tests.

Skipped unless ``ORCAROUTER_API_KEY`` is present in the environment; the key is
read from the environment only and never printed, logged or written anywhere.
"""

from __future__ import annotations

import os
import unittest

from core.orcarouter.catalog import fetch_catalog
from core.orcarouter.client import OrcaApiError, OrcaRouterClient
from core.orcarouter.config import resolve_origins

# Internal smoke-test model used only when the account's cyber tier is locked.
# It is never offered as a product default or fallback in the UI.
INTERNAL_SMOKE_MODEL = "deepseek/deepseek-v4.1-flash"


def _api_key() -> str:
    return (os.environ.get("ORCAROUTER_API_KEY") or "").strip()


@unittest.skipUnless(_api_key(), "ORCAROUTER_API_KEY is not set")
class LiveOrcaRouterTests(unittest.TestCase):
    def setUp(self):
        self.origins = resolve_origins()
        self.client = OrcaRouterClient(self.origins.api_base, _api_key(), timeout=60)

    def test_live_catalog_lists_chat_models(self):
        models = fetch_catalog(self.origins.api_base, _api_key())
        self.assertTrue(models)
        self.assertTrue(any(model.id for model in models))

    def test_live_chat_completion_round_trip(self):
        model = os.environ.get("ORCA_LIVE_MODEL") or "orcarouter/auto"
        try:
            response = self.client.chat(
                model, [{"role": "user", "content": "Reply with the single word: pong"}], max_tokens=256
            )
        except OrcaApiError as error:
            if error.status not in (400, 403, 404):
                raise
            # The account's plan may not expose the default route; fall back to
            # the internal smoke model so connectivity is still exercised.
            response = self.client.chat(
                INTERNAL_SMOKE_MODEL,
                [{"role": "user", "content": "Reply with the single word: pong"}],
                max_tokens=256,
            )
        text = "".join(block.text for block in response.content if getattr(block, "type", "") == "text")
        self.assertTrue(text.strip())


if __name__ == "__main__":
    unittest.main()
