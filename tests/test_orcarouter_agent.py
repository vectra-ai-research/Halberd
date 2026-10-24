"""The agent dispatches by provider and keeps the two credential paths apart."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core.orcarouter import runtime
from core.orcarouter.client import OrcaRouterClient
from core.orcarouter.credentials import CredentialStore
from core.orcarouter.settings import AgentSettings

from tests.support import FAKE_KEY, FakeOrcaServer

MESSAGES = [{"role": "user", "content": "hello"}]


class AgentProviderTests(unittest.TestCase):
    def setUp(self):
        from agent.attack_agent import AttackAgent

        self.AttackAgent = AttackAgent
        self.tmp = tempfile.TemporaryDirectory()
        self.env_path = Path(self.tmp.name) / ".env"
        self.store = CredentialStore(self.env_path, environ={})
        self.settings = AgentSettings(self.env_path, environ={})

        self._patches = [
            mock.patch.object(runtime, "get_agent_settings", lambda: self.settings),
            mock.patch.object(runtime, "credential_store", lambda: self.store),
            mock.patch.object(runtime, "current_credential", lambda: self.store.load()),
        ]
        for patcher in self._patches:
            patcher.start()

    def tearDown(self):
        for patcher in reversed(self._patches):
            patcher.stop()
        self.tmp.cleanup()

    def _agent(self, server=None):
        agent = self.AttackAgent({})
        credential = self.store.load()
        if server is not None and credential is not None:
            client = OrcaRouterClient(server.api_base, credential.api_key, timeout=5)
            agent._orca_client = client
            agent._orca_key = credential.api_key
            agent._orca_generation = credential.generation
            agent._orca_account = credential.account_id
        return agent

    def test_selected_provider_decides_the_wire_protocol(self):
        self.assertEqual(self._agent().provider_id, "anthropic")
        self.settings.set_provider("orcarouter")
        self.assertEqual(self._agent().provider_id, "orcarouter")
        self.assertEqual(self._agent().model_id, "orcarouter/auto")

    def test_orcarouter_call_goes_through_the_openai_compatible_route(self):
        self.settings.set_provider("orcarouter")
        self.store.save_api_key(FAKE_KEY)
        with FakeOrcaServer() as server:
            agent = self._agent(server)
            response = agent.generate_message(MESSAGES, max_tokens=64)
            self.assertEqual(response.content[0].text, "ok")
            chat = [r for r in server.requests if r["path"] == "/v1/chat/completions"]
            self.assertEqual(len(chat), 1)
            self.assertEqual(chat[0]["body"]["model"], "orcarouter/auto")
            self.assertEqual(chat[0]["headers"]["authorization"], f"Bearer {FAKE_KEY}")

    def test_anthropic_provider_never_calls_orcarouter(self):
        probe = mock.Mock(side_effect=AssertionError("OrcaRouter client used for Anthropic"))
        fake = mock.Mock()
        fake.messages.count_tokens.return_value = mock.Mock(input_tokens=10)
        fake.messages.create.return_value = mock.Mock()
        agent = self._agent()
        agent.count_tokens_in_response = lambda response: 5
        with mock.patch.object(runtime, "client", probe), mock.patch.object(
            type(agent), "anthropic", property(lambda self: fake)
        ), mock.patch("agent.attack_agent.time.sleep", lambda *_: None):
            response = agent.generate_message(MESSAGES, max_tokens=8)
        self.assertIs(response, fake.messages.create.return_value)
        self.assertEqual(fake.messages.create.call_args.kwargs["model"], "claude-3-7-sonnet-20250219")
        probe.assert_not_called()

    def test_missing_credential_asks_the_user_to_configure_the_provider(self):
        self.settings.set_provider("orcarouter")
        agent = self._agent()
        result = agent.generate_message(MESSAGES, max_tokens=8)
        self.assertIn("Connect with OrcaRouter", result["error"])
        self.assertFalse(agent.is_ready())

    def test_terminal_401_marks_this_credential_for_reauthentication(self):
        self.settings.set_provider("orcarouter")
        self.store.save_api_key(FAKE_KEY)
        with FakeOrcaServer(chat_status=401, chat_body={"error": {"message": "invalid key"}}) as server:
            agent = self._agent(server)
            result = agent.generate_message(MESSAGES, max_tokens=8)
        self.assertIn("401", result["error"])
        self.assertTrue(self.store.needs_reauth())

    def test_a_late_401_does_not_touch_a_newer_credential(self):
        self.settings.set_provider("orcarouter")
        self.store.save_api_key(FAKE_KEY)
        with FakeOrcaServer(chat_status=401, chat_body={"error": {"message": "invalid key"}}) as server:
            agent = self._agent(server)
            agent._orca_generation = "stale-generation"
            agent.generate_message(MESSAGES, max_tokens=8)
        self.assertFalse(self.store.needs_reauth())

    def test_rate_limit_is_retried_then_reported(self):
        self.settings.set_provider("orcarouter")
        self.store.save_api_key(FAKE_KEY)
        with FakeOrcaServer(
            chat_status=429, chat_body={"error": {"message": "slow down"}}
        ) as server, mock.patch("agent.attack_agent.time.sleep", lambda *_: None):
            agent = self._agent(server)
            result = agent.generate_message(MESSAGES, max_tokens=8)
            attempts = len([r for r in server.requests if r["path"] == "/v1/chat/completions"])
        self.assertGreaterEqual(attempts, 2)
        self.assertIn("rate limit", result["error"].lower())


if __name__ == "__main__":
    unittest.main()
