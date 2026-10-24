"""Model catalog and capability-filter tests."""

from __future__ import annotations

import json
import unittest

from core.orcarouter.catalog import (
    CatalogError,
    CatalogService,
    ModelInfo,
    VERIFIED_SEED,
    filter_models,
    is_chat_model,
    is_compatible,
    parse_catalog,
    sort_for_display,
)

FIXTURE = {
    "object": "list",
    "success": True,
    "data": [
        {"id": "orcarouter/auto", "supported_endpoint_types": ["openai", "openai-response", "anthropic", "gemini"]},
        {"id": "orcarouter/fusion", "supported_endpoint_types": ["openai"], "context_length": 1000000},
        {"id": "orca/orcacyber-ultra-1.0", "supported_endpoint_types": ["openai"],
         "architecture": {"input_modalities": ["text"], "output_modalities": ["text"]}},
        {"id": "openai/gpt-5.5", "supported_endpoint_types": ["openai", "openai-response"],
         "architecture": {"input_modalities": ["text", "image"]},
         "supported_parameters": {"reasoning_efforts": ["low", "medium", "high", "xhigh"]}},
        {"id": "anthropic/claude-opus-4.8", "supported_endpoint_types": ["anthropic"],
         "architecture": {"input_modalities": ["text", "image"]}},
        {"id": "acme/text-only", "supported_endpoint_types": ["openai"],
         "architecture": {"input_modalities": ["text"]}},
        {"id": "acme/undeclared", "supported_endpoint_types": ["openai"]},
        {"id": "acme/embed", "supported_endpoint_types": ["embeddings"]},
        {"id": "acme/image-gen", "supported_endpoint_types": ["image-generation"]},
        {"id": "acme/video", "supported_endpoint_types": ["openai-video"]},
        {"id": "acme/rerank", "supported_endpoint_types": ["jina-rerank"]},
        {"id": "acme/broken", "supported_endpoint_types": "not-a-list"},
        {"id": "", "supported_endpoint_types": ["openai"]},
        "not-a-dict",
    ],
}


class ParseTests(unittest.TestCase):
    def test_parses_bounded_and_validated_records(self):
        models = parse_catalog(FIXTURE)
        ids = [model.id for model in models]
        self.assertIn("orcarouter/auto", ids)
        self.assertNotIn("", ids)
        self.assertNotIn("acme/broken", ids)  # no usable endpoint declaration
        self.assertEqual(len(ids), len(set(ids)))

    def test_retains_metadata(self):
        models = {model.id: model for model in parse_catalog(FIXTURE)}
        gpt = models["openai/gpt-5.5"]
        self.assertEqual(gpt.input_modalities, ("text", "image"))
        self.assertEqual(gpt.reasoning_efforts, ("low", "medium", "high", "xhigh"))
        self.assertEqual(gpt.context_length, None)
        self.assertEqual(models["orcarouter/fusion"].context_length, 1000000)

    def test_accepts_a_bare_list(self):
        self.assertEqual(len(parse_catalog(FIXTURE["data"])), 11)

    def test_rejects_garbage(self):
        self.assertEqual(parse_catalog(None), [])
        self.assertEqual(parse_catalog({"data": "nope"}), [])


class CapabilityFilterTests(unittest.TestCase):
    def setUp(self):
        self.models = parse_catalog(FIXTURE)

    def ids(self, capability="chat", modalities=()):
        return [model.id for model in filter_models(self.models, capability, modalities)]

    def test_text_chat_uses_declared_endpoint_types(self):
        ids = self.ids()
        self.assertIn("orcarouter/auto", ids)
        self.assertIn("orca/orcacyber-ultra-1.0", ids)
        self.assertIn("acme/text-only", ids)
        self.assertIn("openai/gpt-5.5", ids)
        # Non-text routes never appear in a chat list.
        self.assertNotIn("acme/embed", ids)
        self.assertNotIn("acme/image-gen", ids)
        self.assertNotIn("acme/video", ids)
        self.assertNotIn("acme/rerank", ids)

    def test_multimodal_requires_declared_image_input(self):
        ids = self.ids(modalities=("image",))
        self.assertIn("openai/gpt-5.5", ids)
        self.assertIn("anthropic/claude-opus-4.8", ids)
        # Fail closed: undeclared modality never matches.
        self.assertNotIn("acme/undeclared", ids)
        self.assertNotIn("acme/text-only", ids)
        self.assertNotIn("orcarouter/auto", ids)
        self.assertNotIn("orca/orcacyber-ultra-1.0", ids)

    def test_embedding_filter(self):
        self.assertEqual(self.ids("embedding"), ["acme/embed"])

    def test_image_video_rerank_filters(self):
        self.assertEqual(self.ids("image"), ["acme/image-gen"])
        self.assertEqual(self.ids("video"), ["acme/video"])
        self.assertEqual(self.ids("rerank"), ["acme/rerank"])

    def test_empty_declaration_fails_closed(self):
        model = ModelInfo(id="acme/none")
        self.assertFalse(is_chat_model(model))
        self.assertFalse(is_compatible(model, "chat"))

    def test_default_model_sorts_first(self):
        ordered = sort_for_display(self.models)
        self.assertEqual(ordered[0].id, "orcarouter/auto")
        self.assertEqual(ordered[1].id, "orcarouter/fusion")
        self.assertEqual(ordered[2].id, "orca/orcacyber-ultra-1.0")

    def test_options_are_values_not_free_text(self):
        options = [model.option() for model in filter_models(self.models, "chat")]
        self.assertTrue(all(set(option) == {"label", "value"} for option in options))
        self.assertTrue(all(option["value"] for option in options))


class CatalogServiceTests(unittest.TestCase):
    def _service(self, fetcher, clock=None):
        return CatalogService("https://api.orcarouter.ai/v1", ttl=60, fetcher=fetcher, clock=clock or (lambda: 0))

    def test_live_catalog_is_authoritative(self):
        service = self._service(lambda base, key: parse_catalog(FIXTURE))
        result = service.result("chat", api_key="fake")
        self.assertEqual(result.source, "live")
        self.assertFalse(result.degraded)
        # The seed is never mixed into a live result.
        seed_ids = {model.id for model in VERIFIED_SEED}
        live_ids = set(result.ids())
        self.assertNotIn("google/gemini-3.5-flash", live_ids)
        self.assertTrue(seed_ids - live_ids)

    def test_failure_falls_back_to_the_verified_seed(self):
        def boom(base, key):
            raise CatalogError("network_error", "catalog down")

        result = self._service(boom).result("chat", api_key="fake")
        self.assertEqual(result.source, "seed")
        self.assertTrue(result.degraded)
        self.assertEqual(result.error, "catalog down")
        self.assertIn("orcarouter/auto", result.ids())

    def test_seed_keeps_reasoning_and_modality_metadata(self):
        def boom(base, key):
            raise CatalogError("network_error", "catalog down")

        service = self._service(boom)
        seed = {model.id: model for model in service.result("chat", api_key="fake").models}
        self.assertEqual(seed["openai/gpt-5.5"].reasoning_efforts, ("low", "medium", "high", "xhigh"))
        self.assertIn("image", seed["openai/gpt-5.5"].input_modalities)
        image_ids = service.result("chat", ("image",), api_key="fake").ids()
        self.assertIn("openai/gpt-5.5", image_ids)
        self.assertNotIn("deepseek/deepseek-v4-pro", image_ids)

    def test_last_known_good_survives_a_later_outage(self):
        state = {"fail": False}

        def fetcher(base, key):
            if state["fail"]:
                raise CatalogError("network_error", "catalog down")
            return parse_catalog(FIXTURE)

        service = self._service(fetcher)
        first = service.result("chat", api_key="fake")
        self.assertEqual(first.source, "live")
        state["fail"] = True
        second = service.result("chat", api_key="fake", refresh=True)
        self.assertEqual(second.source, "last-known-good")
        self.assertTrue(second.degraded)
        self.assertEqual(second.ids(), first.ids())

    def test_missing_credential_uses_the_seed_not_free_text(self):
        def no_key(base, key):
            raise CatalogError("missing_key", "An OrcaRouter API key is required to load the model catalog.")

        result = self._service(no_key).result("chat", api_key="")
        self.assertEqual(result.source, "seed")
        self.assertTrue(result.options())


if __name__ == "__main__":
    unittest.main()
