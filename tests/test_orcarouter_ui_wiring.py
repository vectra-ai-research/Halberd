"""Static wiring checks for the GUI integration.

These complement the browser evidence: they assert the real components exist
and that the chat page's selector callback returns catalog-derived options.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _source(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class SettingsPanelWiringTests(unittest.TestCase):
    def setUp(self):
        self.source = _source("halberd.py")

    def test_provider_selector_offers_both_providers(self):
        self.assertIn('id="agent-provider-selector"', self.source)
        self.assertIn("provider_options()", self.source)

    def test_both_auth_choices_are_present_side_by_side(self):
        self.assertIn('id="orcarouter-api-key-input-editor"', self.source)
        self.assertIn('id="orcarouter-save-key-button"', self.source)
        self.assertIn('id="orcarouter-connect-button"', self.source)
        self.assertIn("Connect with OrcaRouter", self.source)

    def test_credential_status_is_masked(self):
        self.assertIn("status[\"masked\"]", self.source)
        self.assertNotIn("api_key\", status", self.source)

    def test_cancel_route_and_pagehide_handler_exist(self):
        self.assertIn('/orcarouter/auth/cancel', self.source)
        self.assertIn("keepalive: true", self.source)
        self.assertIn("pagehide", self.source)

    def test_cyber_links_are_shown_in_the_provider_panel(self):
        self.assertIn("PROVIDER_CYBER_PAGE", self.source)
        self.assertIn("PROVIDER_CYBER_MODELS", self.source)


class ChatPageWiringTests(unittest.TestCase):
    def setUp(self):
        self.source = _source("pages/attack_agent.py")
        self.tree = ast.parse(self.source)

    def test_model_selector_is_a_dropdown_not_free_text(self):
        self.assertIn('id="agent-model-selector"', self.source)
        self.assertIn("dcc.Dropdown(", self.source)
        self.assertNotIn('id="agent-model-input"', self.source)

    def test_selector_callback_is_wired_to_catalog_options(self):
        functions = {node.name: node for node in ast.walk(self.tree) if isinstance(node, ast.FunctionDef)}
        callback = functions["update_agent_model_options"]
        source = ast.get_source_segment(self.source, callback)
        self.assertIn("runtime.model_catalog", source)
        self.assertIn("build_model_options", source)
        self.assertIn("attachment-modalities-store", self.source)

    def test_attachment_changes_recompute_the_selector(self):
        functions = {node.name: node for node in ast.walk(self.tree) if isinstance(node, ast.FunctionDef)}
        callback = functions["update_agent_model_options"]
        decorator_text = ast.get_source_segment(self.source, callback.decorator_list[0])
        self.assertIn("attachment-modalities-store", decorator_text)
        self.assertIn("agent-provider-store", decorator_text)

    def test_chat_readiness_uses_the_selected_provider(self):
        self.assertIn("chatbot_agent.is_ready()", self.source)
        self.assertIn("OrcaRouter API key", self.source)


class PackageHygieneTests(unittest.TestCase):
    def test_our_modules_contain_no_client_secret(self):
        for path in (ROOT / "core" / "orcarouter").glob("*.py"):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("client_secret", text, path.name)

    def test_exchange_url_uses_the_auth_api_path(self):
        from core.orcarouter.config import Origins, exchange_url

        url = exchange_url(Origins("https://www.orcarouter.ai", "https://api.orcarouter.ai/v1"))
        self.assertEqual(url, "https://www.orcarouter.ai/api/v1/auth/keys")

    def test_no_real_looking_key_is_committed(self):
        import re
        import subprocess

        pattern = re.compile(r"sk-orca-[A-Za-z0-9]{20,}")
        tracked = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "-z"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.split("\0")
        offenders = []
        for name in tracked:
            if not name:
                continue
            path = ROOT / name
            if not path.is_file() or path.parts[-1] == "orca-evidence":
                continue
            if path.suffix not in {".py", ".md", ".json", ".yml", ".yaml", ".txt", ".env", ""}:
                continue
            if "tests" in path.parts:
                continue  # fake fixtures live here by design
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            if pattern.search(text):
                offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
