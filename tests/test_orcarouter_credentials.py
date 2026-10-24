"""Credential seam tests: both adapters must yield the same credential shape."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from core.orcarouter.credentials import (
    CredentialError,
    CredentialStore,
    OrcaCredential,
    mask_key,
    redact,
)

FAKE_KEY = "sk-orca-TESTKEY0000000000000000"
OTHER_KEY = "sk-orca-SECOND0000000000000000000"


class CredentialStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env_path = Path(self.tmp.name) / ".env"
        self.environ: dict[str, str] = {}
        self.store = CredentialStore(self.env_path, environ=self.environ)

    def tearDown(self):
        self.tmp.cleanup()

    # ------------------------------------------------------------ API key
    def test_api_key_adapter_saves_reads_and_clears(self):
        self.assertIsNone(self.store.load())
        credential = self.store.save_api_key(FAKE_KEY)
        self.assertIsInstance(credential, OrcaCredential)
        self.assertEqual(credential.source, "api_key")
        self.assertEqual(credential.api_key, FAKE_KEY)
        self.assertEqual(self.store.load().api_key, FAKE_KEY)
        self.assertEqual(self.environ["ORCAROUTER_API_KEY"], FAKE_KEY)

        self.store.clear()
        self.assertIsNone(self.store.load())
        self.assertNotIn("ORCAROUTER_API_KEY", self.environ)
        self.assertNotIn(FAKE_KEY, self.env_path.read_text())

    def test_saving_does_not_clobber_unrelated_env_lines(self):
        self.env_path.write_text('ANTHROPIC_API_KEY="keep-me"\n# comment\n')
        self.store.save_api_key(FAKE_KEY)
        text = self.env_path.read_text()
        self.assertIn('ANTHROPIC_API_KEY="keep-me"', text)
        self.assertIn("# comment", text)
        self.assertIn(FAKE_KEY, text)

    def test_invalid_keys_are_rejected(self):
        for value in ("", "   ", "short", "sk-orca-has space in it"):
            with self.assertRaises(CredentialError):
                self.store.save_api_key(value)

    def test_environment_wins_over_file(self):
        self.store.save_api_key(FAKE_KEY)
        self.environ["ORCAROUTER_API_KEY"] = OTHER_KEY
        self.assertEqual(self.store.load().api_key, OTHER_KEY)

    def test_masking_never_reveals_the_key(self):
        masked = mask_key(FAKE_KEY)
        self.assertNotEqual(masked, FAKE_KEY)
        self.assertTrue(masked.startswith("sk-orca-"))
        self.assertLessEqual(len(masked), 14)
        self.assertNotIn(FAKE_KEY, repr(self.store.save_api_key(FAKE_KEY)))

    def test_redaction_strips_keys_from_messages(self):
        message = f"upstream said the key {FAKE_KEY} is invalid"
        cleaned = redact(message)
        self.assertNotIn(FAKE_KEY, cleaned)
        self.assertIn("sk-orca-…", cleaned)

    # ---------------------------------------------------------------- PKCE
    def test_pkce_adapter_yields_the_same_credential_type(self):
        pasted = self.store.save_api_key(FAKE_KEY)
        minted = self.store.save_pkce_credential(OTHER_KEY, "user-7", "api")
        self.assertIsInstance(minted, OrcaCredential)
        self.assertEqual(type(pasted), type(minted))
        self.assertEqual(minted.source, "pkce")
        self.assertEqual(minted.account_id, "user-7")
        self.assertEqual(minted.scope, "api")
        self.assertEqual(self.store.load().source, "pkce")
        self.assertEqual(self.store.load().account_id, "user-7")

    def test_granted_scope_must_permit_inference(self):
        with self.assertRaises(CredentialError):
            self.store.save_pkce_credential(FAKE_KEY, "user-7", "connector")
        self.assertIsNone(self.store.load())

    def test_stale_exchange_cannot_overwrite_a_newer_credential(self):
        self.store.save_api_key(FAKE_KEY)
        stale_generation = self.store.generation()
        self.store.save_api_key(OTHER_KEY)  # replaced while the exchange was in flight
        with self.assertRaises(CredentialError):
            self.store.save_pkce_credential(FAKE_KEY, "user-7", "api", expected_generation=stale_generation)
        self.assertEqual(self.store.load().api_key, OTHER_KEY)

    # ------------------------------------------------------- 401 generation
    def test_needs_reauth_only_marks_the_exact_generation(self):
        credential = self.store.save_api_key(FAKE_KEY)
        self.assertTrue(self.store.mark_needs_reauth(credential.account_id, credential.generation))
        self.assertTrue(self.store.needs_reauth())

        newer = self.store.save_api_key(OTHER_KEY)
        self.assertFalse(self.store.needs_reauth())
        # A late 401 from the old request must not taint the new credential.
        self.assertFalse(self.store.mark_needs_reauth(None, credential.generation))
        self.assertFalse(self.store.needs_reauth())
        self.assertTrue(newer.generation > credential.generation)

    def test_needs_reauth_is_cleared_by_a_successful_reconnect(self):
        credential = self.store.save_pkce_credential(FAKE_KEY, "user-7", "api")
        self.store.mark_needs_reauth("user-7", credential.generation)
        self.assertTrue(self.store.needs_reauth())
        self.store.save_pkce_credential(OTHER_KEY, "user-7", "api")
        self.assertFalse(self.store.needs_reauth())

    def test_status_contains_no_secret(self):
        self.store.save_api_key(FAKE_KEY)
        status = self.store.status()
        self.assertTrue(status["configured"])
        self.assertNotIn(FAKE_KEY, str(status))
        self.assertEqual(status["source"], "api_key")


if __name__ == "__main__":
    unittest.main()
