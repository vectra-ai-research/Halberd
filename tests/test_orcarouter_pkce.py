"""OAuth 2.0 + PKCE tests.

The authorization code, verifier and keys in this module are fake literals.
The OrcaRouter endpoints are replaced by a loopback server; the "browser" is
simulated by performing the GET the browser would perform on the redirect URI.
"""

from __future__ import annotations

import base64
import hashlib
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from core.orcarouter.config import Origins
from core.orcarouter.credentials import CredentialStore
from core.orcarouter.pkce import (
    OrcaAuthManager,
    PkceError,
    build_authorize_url,
    code_challenge,
    exchange_code,
    new_code_verifier,
    new_state,
)

from tests.support import FAKE_KEY, FakeOrcaServer


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _get(url: str, timeout: float = 5.0) -> int:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


class PkcePrimitiveTests(unittest.TestCase):
    def test_verifier_is_fresh_and_high_entropy(self):
        first = new_code_verifier()
        second = new_code_verifier()
        self.assertNotEqual(first, second)
        self.assertGreaterEqual(len(first), 43)
        self.assertNotIn("=", first)
        decoded = base64.urlsafe_b64decode(first + "=" * (-len(first) % 4))
        self.assertEqual(len(decoded), 32)

    def test_challenge_is_unpadded_base64url_sha256(self):
        verifier = "test-verifier-value"
        expected = _b64url(hashlib.sha256(verifier.encode()).digest())
        self.assertEqual(code_challenge(verifier), expected)
        self.assertNotIn("=", code_challenge(verifier))
        self.assertNotEqual(code_challenge(verifier), verifier)

    def test_state_is_random(self):
        self.assertNotEqual(new_state(), new_state())

    def test_authorize_url_uses_the_auth_origin_and_s256(self):
        origins = Origins("https://www.orcarouter.ai", "https://api.orcarouter.ai/v1")
        verifier = new_code_verifier()
        state = new_state()
        url = build_authorize_url(origins, "http://127.0.0.1:5555/cb", code_challenge(verifier), state)
        parts = urlsplit(url)
        self.assertEqual(parts.scheme, "https")
        self.assertEqual(parts.netloc, "www.orcarouter.ai")
        self.assertEqual(parts.path, "/auth")
        params = parse_qs(parts.query)
        self.assertEqual(params["code_challenge_method"], ["S256"])
        self.assertEqual(params["callback_url"], ["http://127.0.0.1:5555/cb"])
        self.assertEqual(params["state"], [state])
        self.assertEqual(params["app_name"], ["Halberd"])
        self.assertEqual(params["scope"], ["api"])
        # The verifier must never appear in the URL.
        self.assertNotIn(verifier, url)
        self.assertNotIn("code_verifier", params)


class PkceFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env_path = Path(self.tmp.name) / ".env"
        self.environ: dict[str, str] = {}
        self.store = CredentialStore(self.env_path, environ=self.environ)

    def tearDown(self):
        self.tmp.cleanup()

    def _manager(self, auth_base, timeout=6.0):
        return OrcaAuthManager(
            self.store,
            origins=Origins(auth_base, auth_base + "/v1"),
            timeout=timeout,
            browser_open=lambda *a, **k: None,
        )

    @staticmethod
    def _params(url: str) -> dict:
        return {key: values[0] for key, values in parse_qs(urlsplit(url).query).items()}

    def test_flow_a_round_trip_persists_a_single_credential(self):
        with FakeOrcaServer() as server:
            manager = self._manager(server.auth_base)
            started = manager.begin(open_browser=False)
            params = self._params(started["authorize_url"])
            self.assertEqual(started["state"], "pending")

            code = _get(params["callback_url"] + "?code=fake-code&state=" + params["state"])
            self.assertEqual(code, 200)
            final = manager.wait(timeout=6)

            self.assertEqual(final["state"], "success", final)
            credential = self.store.load()
            self.assertIsNotNone(credential)
            self.assertEqual(credential.source, "pkce")
            self.assertEqual(credential.account_id, "user-42")
            self.assertEqual(credential.api_key, FAKE_KEY)

            exchanges = [r for r in server.requests if r["path"].startswith("/api/v1/auth/keys")]
            self.assertEqual(len(exchanges), 1)
            body = exchanges[0]["body"]
            self.assertEqual(body["code"], "fake-code")
            self.assertEqual(body["code_challenge_method"], "S256")
            self.assertIn("code_verifier", body)
            self.assertTrue(body["code_verifier"])

    def test_exchange_uses_the_auth_origin_not_the_inference_origin(self):
        with FakeOrcaServer() as server:
            manager = self._manager(server.auth_base)
            started = manager.begin(open_browser=False)
            params = self._params(started["authorize_url"])
            _get(params["callback_url"] + "?code=fake-code&state=" + params["state"])
            manager.wait(timeout=6)
            paths = server.paths()
            self.assertIn("/api/v1/auth/keys", paths)
            # The classic mistake: /v1/auth/keys on the relay.
            self.assertNotIn("/v1/auth/keys", paths)

    def test_state_mismatch_is_rejected_before_the_code_is_used(self):
        with FakeOrcaServer() as server:
            manager = self._manager(server.auth_base)
            started = manager.begin(open_browser=False)
            params = self._params(started["authorize_url"])
            status = _get(params["callback_url"] + "?code=fake-code&state=wrong-state")
            self.assertEqual(status, 400)
            final = manager.wait(timeout=6)
            self.assertEqual(final["state"], "error")
            self.assertEqual(final["code"], "state_mismatch")
            self.assertIsNone(self.store.load())
            self.assertEqual([r for r in server.requests if "auth/keys" in r["path"]], [])

    def test_denial_ends_the_attempt_cleanly(self):
        with FakeOrcaServer() as server:
            manager = self._manager(server.auth_base)
            started = manager.begin(open_browser=False)
            params = self._params(started["authorize_url"])
            _get(params["callback_url"] + "?error=access_denied&state=" + params["state"])
            final = manager.wait(timeout=6)
            self.assertEqual(final["state"], "error")
            self.assertEqual(final["code"], "access_denied")
            self.assertIsNone(self.store.load())

    def test_timeout_ends_the_attempt_and_releases_the_listener(self):
        with FakeOrcaServer() as server:
            manager = self._manager(server.auth_base, timeout=0.4)
            manager.begin(open_browser=False)
            final = manager.wait(timeout=3)
            self.assertEqual(final["state"], "error")
            self.assertEqual(final["code"], "timeout")

    def test_explicit_cancel_is_terminal_then_a_second_login_can_start(self):
        with FakeOrcaServer() as server:
            manager = self._manager(server.auth_base)
            manager.begin(open_browser=False)
            cancelled = manager.cancel()
            self.assertEqual(cancelled["state"], "cancelled")
            self.assertIn("cancelled", cancelled["message"].lower())

            second = manager.begin(open_browser=False)
            params = self._params(second["authorize_url"])
            _get(params["callback_url"] + "?code=fake-code&state=" + params["state"])
            final = manager.wait(timeout=6)
            self.assertEqual(final["state"], "success", final)

    def test_pagehide_cancel_clears_state_without_remounting(self):
        with FakeOrcaServer() as server:
            manager = self._manager(server.auth_base)
            manager.begin(open_browser=False)
            status = manager.cancel(pagehide=True)
            self.assertEqual(status["state"], "cancelled")
            self.assertIn("page closed", status["message"])
            # A second attempt must be possible from the same page lifetime.
            manager.begin(open_browser=False)
            self.assertEqual(manager.status()["state"], "pending")
            manager.cancel()

    def test_stale_cancel_cannot_kill_a_newer_attempt(self):
        with FakeOrcaServer() as server:
            manager = self._manager(server.auth_base)
            old = manager.begin(open_browser=False)
            manager.cancel()
            new = manager.begin(open_browser=False)
            manager.cancel(generation=old["generation"])
            self.assertEqual(manager.status()["state"], "pending")
            manager.cancel(generation=new["generation"])
            self.assertEqual(manager.status()["state"], "cancelled")

    def test_scope_downgrade_is_refused(self):
        with FakeOrcaServer(exchange_body={"key": FAKE_KEY, "user_id": "u1", "scope": "connector"}) as server:
            manager = self._manager(server.auth_base)
            started = manager.begin(open_browser=False)
            params = self._params(started["authorize_url"])
            _get(params["callback_url"] + "?code=fake-code&state=" + params["state"])
            final = manager.wait(timeout=6)
            self.assertEqual(final["state"], "error")
            self.assertEqual(final["code"], "scope_denied")
            self.assertIsNone(self.store.load())

    def test_rejected_code_maps_to_actionable_error(self):
        with FakeOrcaServer(exchange_status=403) as server:
            manager = self._manager(server.auth_base)
            started = manager.begin(open_browser=False)
            params = self._params(started["authorize_url"])
            _get(params["callback_url"] + "?code=fake-code&state=" + params["state"])
            final = manager.wait(timeout=6)
            self.assertEqual(final["state"], "error")
            self.assertEqual(final["code"], "code_rejected")
            self.assertIsNone(self.store.load())

    def test_rate_limited_exchange_is_reported(self):
        with FakeOrcaServer(exchange_status=429) as server:
            manager = self._manager(server.auth_base)
            started = manager.begin(open_browser=False)
            params = self._params(started["authorize_url"])
            _get(params["callback_url"] + "?code=fake-code&state=" + params["state"])
            final = manager.wait(timeout=6)
            self.assertEqual(final["code"], "rate_limited")

    def test_network_failure_is_terminal(self):
        manager = self._manager("http://127.0.0.1:1", timeout=3)
        started = manager.begin(open_browser=False)
        params = self._params(started["authorize_url"])
        _get(params["callback_url"] + "?code=fake-code&state=" + params["state"])
        final = manager.wait(timeout=5)
        self.assertEqual(final["state"], "error")
        self.assertEqual(final["code"], "network_error")

    def test_verifier_never_appears_in_status_or_urls(self):
        with FakeOrcaServer() as server:
            manager = self._manager(server.auth_base)
            started = manager.begin(open_browser=False)
            params = self._params(started["authorize_url"])
            _get(params["callback_url"] + "?code=fake-code&state=" + params["state"])
            final = manager.wait(timeout=6)
            body = [r for r in server.requests if "auth/keys" in r["path"]][0]["body"]
            verifier = body["code_verifier"]
            self.assertNotIn(verifier, str(started))
            self.assertNotIn(verifier, str(final))
            self.assertNotIn(FAKE_KEY, str(final))

    def test_exchange_helper_reports_403_without_echoing_the_code(self):
        with FakeOrcaServer(exchange_status=403) as server:
            with self.assertRaises(PkceError) as ctx:
                exchange_code(Origins(server.auth_base, server.api_base), "secret-code", "verifier-value")
            self.assertEqual(ctx.exception.code, "code_rejected")
            self.assertNotIn("secret-code", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
