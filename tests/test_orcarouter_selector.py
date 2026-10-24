"""Model-selector behaviour: options always come from the catalog."""

from __future__ import annotations

import unittest

from core.orcarouter.catalog import CatalogResult, ModelInfo
from core.orcarouter.selector import build_model_options

CHAT = [
    ModelInfo(id="orcarouter/auto", endpoint_types=("openai", "anthropic")),
    ModelInfo(id="orcacyber-ultra-1.0", endpoint_types=("openai",), input_modalities=("text",)),
]
IMAGE = [
    ModelInfo(id="openai/gpt-5.5", input_modalities=("text", "image"), endpoint_types=("openai",)),
    ModelInfo(id="acme/text-only", input_modalities=("text",), endpoint_types=("openai",)),
]


def result(models, source="live", degraded=False, error=None):
    return CatalogResult(models=list(models), source=source, degraded=degraded, error=error, total=len(models))


class SelectorTests(unittest.TestCase):
    def test_anthropic_provider_keeps_the_hidden_default(self):
        state = build_model_options("anthropic", result(CHAT), None, None)
        self.assertFalse(state.visible)
        self.assertEqual(state.options, [])
        self.assertTrue(state.disabled)

    def test_orcarouter_options_come_from_the_catalog(self):
        state = build_model_options("orcarouter", result(CHAT), None, "orcarouter/auto")
        self.assertTrue(state.visible)
        self.assertFalse(state.disabled)
        self.assertEqual(state.ids, ["orcarouter/auto", "orcacyber-ultra-1.0"])
        self.assertEqual(state.value, "orcarouter/auto")

    def test_preferred_model_is_selected_when_available(self):
        state = build_model_options("orcarouter", result(CHAT), None, "orcacyber-ultra-1.0")
        self.assertEqual(state.value, "orcacyber-ultra-1.0")

    def test_image_attachment_filters_to_image_declared_chat_models(self):
        state = build_model_options("orcarouter", result([IMAGE[0]]), None, "orcarouter/auto", modalities=["image"])
        self.assertEqual(state.ids, ["openai/gpt-5.5"])
        self.assertEqual(state.value, "openai/gpt-5.5")

    def test_incompatible_current_model_is_cleared_with_a_notice(self):
        state = build_model_options(
            "orcarouter", result([IMAGE[0]]), "acme/text-only", "acme/text-only", modalities=["image"]
        )
        self.assertNotEqual(state.value, "acme/text-only")
        self.assertEqual(state.value, "openai/gpt-5.5")
        self.assertTrue(any("does not accept this attachment" in text for _severity, text in state.notices))

    def test_degraded_catalog_is_labelled(self):
        state = build_model_options(
            "orcarouter", result(CHAT, source="seed", degraded=True, error="catalog down"), None, None
        )
        self.assertTrue(state.degraded)
        self.assertTrue(any("seed catalog" in text for _severity, text in state.notices))
        self.assertTrue(any("catalog down" in text for _severity, text in state.notices))

    def test_pdf_is_flagged_as_unsupported_for_orcarouter(self):
        state = build_model_options("orcarouter", result(CHAT), None, None, modalities=["document"])
        self.assertTrue(any("Anthropic provider" in text for _severity, text in state.notices))

    def test_empty_catalog_disables_the_selector_instead_of_free_text(self):
        state = build_model_options("orcarouter", result([]), None, None)
        self.assertTrue(state.disabled)
        self.assertIsNone(state.value)
        self.assertEqual(state.options, [])


if __name__ == "__main__":
    unittest.main()
