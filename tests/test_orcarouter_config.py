"""Origin policy, provider registry and agent-settings tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core.orcarouter.config import ConfigError, resolve_origins
from core.orcarouter.providers import get_provider, provider_options
from core.orcarouter.settings import AgentSettings


class OriginTests(unittest.TestCase):
    def test_public_defaults(self):
        origins = resolve_origins({})
        self.assertEqual(origins.auth_base, "https://www.orcarouter.ai")
        self.assertEqual(origins.api_base, "https://api.orcarouter.ai/v1")

    def test_explicit_auth_override_does_not_move_inference(self):
        origins = resolve_origins({"ORCA_AUTH_BASE_URL": "https://sso.example.test"})
        self.assertEqual(origins.auth_base, "https://sso.example.test")
        self.assertEqual(origins.api_base, "https://api.orcarouter.ai/v1")

    def test_explicit_api_override_does_not_move_auth(self):
        origins = resolve_origins({"ORCA_API_BASE_URL": "https://relay.example.test/v1"})
        self.assertEqual(origins.auth_base, "https://www.orcarouter.ai")
        self.assertEqual(origins.api_base, "https://relay.example.test/v1")

    def test_shared_self_hosted_base_is_used_for_both(self):
        origins = resolve_origins({"ORCA_BASE_URL": "http://127.0.0.1:9000"})
        self.assertEqual(origins.auth_base, "http://127.0.0.1:9000")
        self.assertEqual(origins.api_base, "http://127.0.0.1:9000/v1")

    def test_explicit_overrides_win_over_the_shared_base(self):
        origins = resolve_origins(
            {
                "ORCA_BASE_URL": "http://127.0.0.1:9000",
                "ORCA_AUTH_BASE_URL": "https://auth.example.test",
                "ORCA_API_BASE_URL": "https://api.example.test/v1",
            }
        )
        self.assertEqual(origins.auth_base, "https://auth.example.test")
        self.assertEqual(origins.api_base, "https://api.example.test/v1")

    def test_plain_http_is_only_allowed_on_loopback(self):
        with self.assertRaises(ConfigError):
            resolve_origins({"ORCA_API_BASE_URL": "http://api.orcarouter.ai/v1"})
        with self.assertRaises(ConfigError):
            resolve_origins({"ORCA_AUTH_BASE_URL": "http://www.orcarouter.ai"})
        resolve_origins({"ORCA_AUTH_BASE_URL": "http://localhost:8050"})

    def test_api_origin_is_never_derived_from_the_auth_origin(self):
        origins = resolve_origins({"ORCA_AUTH_BASE_URL": "https://www.orcarouter.ai"})
        self.assertNotIn("www.orcarouter.ai", origins.api_base)
        self.assertIn("api.orcarouter.ai", origins.api_base)


class ProviderRegistryTests(unittest.TestCase):
    def test_both_providers_are_registered(self):
        values = [option["value"] for option in provider_options()]
        self.assertEqual(values, ["anthropic", "orcarouter"])

    def test_orcarouter_is_labelled_and_has_a_default_model(self):
        spec = get_provider("orcarouter")
        self.assertEqual(spec.label, "OrcaRouter Cyber Inference")
        self.assertTrue(spec.label.startswith("OrcaRouter"))
        self.assertEqual(spec.default_model, "orcarouter/auto")
        self.assertTrue(spec.supports_oauth)

    def test_unknown_provider_falls_back_to_anthropic(self):
        self.assertEqual(get_provider("nope").id, "anthropic")


class AgentSettingsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / ".env"
        self.environ: dict[str, str] = {}
        self.settings = AgentSettings(self.path, environ=self.environ)

    def tearDown(self):
        self.tmp.cleanup()

    def test_default_provider_is_anthropic(self):
        self.assertEqual(self.settings.provider(), "anthropic")

    def test_switching_to_orcarouter_selects_the_default_model(self):
        snapshot = self.settings.set_provider("orcarouter")
        self.assertEqual(snapshot["provider"], "orcarouter")
        self.assertEqual(snapshot["model"], "orcarouter/auto")
        self.assertIn("HALBERD_AGENT_PROVIDER", self.path.read_text())

    def test_model_must_be_in_the_filtered_options(self):
        from core.orcarouter.catalog import ModelInfo

        options = [ModelInfo(id="orcarouter/auto", endpoint_types=("openai",))]
        self.settings.set_provider("orcarouter")
        self.settings.set_model("orcarouter/auto", options)
        with self.assertRaises(ValueError):
            self.settings.set_model("acme/not-listed", options)

    def test_settings_survive_a_restart(self):
        self.settings.set_provider("orcarouter")
        restored = AgentSettings(self.path, environ={})
        self.assertEqual(restored.provider(), "orcarouter")


if __name__ == "__main__":
    unittest.main()
