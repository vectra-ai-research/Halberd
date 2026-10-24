"""Both acquisition adapters must feed the same downstream path."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core.orcarouter.catalog import fetch_catalog
from core.orcarouter.client import OrcaRouterClient
from core.orcarouter.credentials import CredentialStore

from tests.support import FAKE_KEY, FakeOrcaServer

MINTED_KEY = "sk-orca-MINTED00000000000000000"


class DualAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = CredentialStore(Path(self.tmp.name) / ".env", environ={})

    def tearDown(self):
        self.tmp.cleanup()

    def test_both_adapters_return_the_same_credential_shape(self):
        pasted = self.store.save_api_key(FAKE_KEY)
        minted = self.store.save_pkce_credential(MINTED_KEY, "user-9", "api")
        self.assertEqual(type(pasted), type(minted))
        self.assertEqual(pasted.api_key, FAKE_KEY)
        self.assertEqual(minted.api_key, MINTED_KEY)
        self.assertNotEqual(pasted.source, minted.source)
        for credential in (pasted, minted):
            self.assertTrue(credential.api_key)
            self.assertEqual(credential.scope, "api")
            self.assertNotIn(credential.api_key, repr(credential))

    def test_downstream_inference_does_not_care_which_adapter_was_used(self):
        pasted = self.store.save_api_key(FAKE_KEY)
        minted = self.store.save_pkce_credential(MINTED_KEY, "user-9", "api")
        with FakeOrcaServer() as server:
            for credential in (pasted, minted):
                client = OrcaRouterClient(server.api_base, credential.api_key)
                response = client.chat("orcarouter/auto", [{"role": "user", "content": "hi"}])
                self.assertEqual(response.content[0].text, "ok")
        auth_calls = [r for r in server.requests if "auth/keys" in r["path"]]
        self.assertEqual(auth_calls, [])

    def test_model_discovery_does_not_care_which_adapter_was_used(self):
        pasted = self.store.save_api_key(FAKE_KEY)
        minted = self.store.save_pkce_credential(MINTED_KEY, "user-9", "api")
        with FakeOrcaServer() as server:
            first = [model.id for model in fetch_catalog(server.api_base, pasted.api_key)]
            second = [model.id for model in fetch_catalog(server.api_base, minted.api_key)]
        self.assertEqual(first, second)
        self.assertIn("orcarouter/auto", first)

    def test_auth_and_inference_use_different_origins_during_login(self):
        from core.orcarouter.config import Origins
        from core.orcarouter.pkce import OrcaAuthManager

        with FakeOrcaServer() as server:
            manager = OrcaAuthManager(
                self.store,
                origins=Origins(server.auth_base, server.api_base),
                timeout=5,
                browser_open=lambda *a, **k: None,
            )
            started = manager.begin(open_browser=False)
            from urllib.parse import parse_qs, urlsplit

            params = {k: v[0] for k, v in parse_qs(urlsplit(started["authorize_url"]).query).items()}
            self.assertTrue(started["authorize_url"].startswith(server.auth_base + "/auth"))
            import urllib.request

            with urllib.request.urlopen(params["callback_url"] + "?code=c&state=" + params["state"], timeout=5) as response:
                response.read()
            self.assertEqual(manager.wait(timeout=5)["state"], "success")
            paths = server.paths()
            self.assertEqual(paths, ["/api/v1/auth/keys"])


if __name__ == "__main__":
    unittest.main()
