"""OAuth 2.0 + PKCE connect flow for OrcaRouter (Flow A, loopback redirect).

Halberd is a server-side Dash application that always runs its own local
process, and the user's browser is on the same host, so the loopback redirect
flow returns the authorization code automatically. S256 is always sent: the
consent screen may hand the user a code to paste ("Show me a code"), so the
challenge must be bound to the verifier even on the redirect path.

The verifier never leaves this process until the exchange, never appears in a
URL, and is never logged.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import queue
import secrets
import threading
import urllib.error
import urllib.request
import webbrowser
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

from .config import (
    APP_NAME,
    DEFAULT_SCOPE,
    Origins,
    authorize_url,
    exchange_url,
    resolve_origins,
)
from .credentials import CredentialError, CredentialStore, OrcaCredential, redact

CALLBACK_PATH = "/cb"
DEFAULT_TIMEOUT = 180


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def new_code_verifier() -> str:
    """A fresh 256-bit verifier from the cryptographic RNG (per attempt)."""
    return _b64url(secrets.token_bytes(32))


def code_challenge(verifier: str) -> str:
    """``base64url(sha256(verifier))`` without padding."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return _b64url(digest)


def new_state() -> str:
    return _b64url(secrets.token_bytes(16))


class PkceError(Exception):
    """A terminal authorization failure with a user-actionable code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def build_authorize_url(
    origins: Origins,
    redirect_uri: str,
    challenge: str,
    state: str,
    app_name: str = APP_NAME,
    scope: str = DEFAULT_SCOPE,
) -> str:
    params = {
        "callback_url": redirect_uri,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        "app_name": app_name,
        "scope": scope,
    }
    return authorize_url(origins) + "?" + urlencode(params)


class LoopbackReceiver:
    """One-shot HTTP listener bound to ``127.0.0.1:0`` for the auth callback."""

    def __init__(self, path: str = CALLBACK_PATH):
        self._path = path
        self._events: queue.Queue = queue.Queue(maxsize=1)
        self._expected_state: str | None = None
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._closed = False

    # -- lifecycle ---------------------------------------------------------
    def start(self, expected_state: str) -> str:
        self._expected_state = expected_state
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):  # never log query strings
                return

            def do_GET(self):  # noqa: N802 - stdlib naming
                parsed = urlsplit(self.path)
                if parsed.path != receiver._path:
                    self._respond(404, "<p>Not found.</p>")
                    return
                params = parse_qs(parsed.query, keep_blank_values=True)
                # Compare the state before touching the code.
                returned_state = (params.get("state") or [""])[0]
                if not receiver._state_matches(returned_state):
                    self._respond(400, "<p>Authorization failed: state mismatch. You can close this tab.</p>")
                    receiver._deliver(("error", "state_mismatch", "The authorization response did not match this request."))
                    return
                error = (params.get("error") or [""])[0]
                if error:
                    self._respond(200, "<p>Authorization was not granted. You can close this tab.</p>")
                    receiver._deliver(("error", "access_denied", "Authorization was denied."))
                    return
                code = (params.get("code") or [""])[0]
                if not code:
                    self._respond(400, "<p>Authorization failed: no code returned. You can close this tab.</p>")
                    receiver._deliver(("error", "invalid_response", "No authorization code was returned."))
                    return
                self._respond(200, "<p>Connected. You can close this tab and return to Halberd.</p>")
                receiver._deliver(("code", code, ""))

            def _respond(self, status: int, body: str):
                payload = body.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(payload)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
        self._thread.start()
        port = server.server_address[1]
        return f"http://127.0.0.1:{port}{self._path}"

    def _state_matches(self, returned: str) -> bool:
        expected = self._expected_state or ""
        if not returned or not expected:
            return False
        return hmac.compare_digest(returned, expected)

    def _deliver(self, event: tuple) -> None:
        try:
            self._events.put_nowait(event)
        except queue.Full:
            pass

    def wait(self, timeout: float = DEFAULT_TIMEOUT) -> str:
        try:
            kind, value, message = self._events.get(timeout=timeout)
        except queue.Empty:
            raise PkceError("timeout", "The authorization window closed before it was approved.") from None
        finally:
            self.close()
        if kind == "error":
            raise PkceError(value, message)
        return value

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        server = self._server
        if server is not None:
            try:
                server.shutdown()
            except Exception:
                pass
            try:
                server.server_close()
            except Exception:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2)


# ---------------------------------------------------------------- exchange
def exchange_code(
    origins: Origins,
    code: str,
    verifier: str,
    timeout: float = 30,
    opener=None,
) -> dict:
    """Redeem the authorization code at ``{auth_base}/api/v1/auth/keys``."""
    body = json.dumps(
        {"code": code, "code_verifier": verifier, "code_challenge_method": "S256"}
    ).encode("utf-8")
    request = urllib.request.Request(
        exchange_url(origins),
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    open_fn = opener or urllib.request.urlopen
    try:
        with open_fn(request, timeout=timeout) as response:
            payload = response.read(512 * 1024)
            status = getattr(response, "status", 200)
    except urllib.error.HTTPError as exc:
        status = exc.code
        try:
            detail = exc.read(8 * 1024).decode("utf-8", "replace")
        except Exception:
            detail = ""
        raise _exchange_error(status, detail) from None
    except urllib.error.URLError as exc:
        raise PkceError("network_error", f"Could not reach OrcaRouter: {exc.reason}") from None
    except TimeoutError:
        raise PkceError("network_error", "The OrcaRouter authorization request timed out.") from None

    if status >= 400:
        raise _exchange_error(status, "")
    try:
        data = json.loads(payload.decode("utf-8"))
    except ValueError:
        raise PkceError("invalid_response", "OrcaRouter returned an unreadable response.") from None
    key = data.get("key") if isinstance(data, dict) else None
    if not isinstance(key, str) or not key.strip():
        raise PkceError("invalid_response", "OrcaRouter did not return a key.")
    return {
        "key": key.strip(),
        "user_id": data.get("user_id") or None,
        "scope": (data.get("scope") or "").strip(),
    }


def _exchange_error(status: int, detail: str) -> PkceError:
    if status == 400:
        return PkceError(
            "invalid_request",
            "OrcaRouter rejected the authorization request (usually a challenge-method mismatch). Start again.",
        )
    if status == 403:
        return PkceError(
            "code_rejected",
            "That authorization code is unknown, expired, already used, or does not match this request.",
        )
    if status == 429:
        return PkceError(
            "rate_limited",
            "Too many authorizations in 24 hours. Reuse the saved key or try again later.",
        )
    if status >= 500:
        return PkceError("server_error", "OrcaRouter is unavailable right now. Try again shortly.")
    safe_detail = redact((detail or "").strip())[:200]
    return PkceError("exchange_failed", f"OrcaRouter rejected the exchange ({status}). {safe_detail}".strip())


# ---------------------------------------------------------------- manager
@dataclass
class AuthStatus:
    state: str = "idle"  # idle | pending | success | error | cancelled
    generation: int = 0
    authorize_url: str = ""
    message: str = ""
    account_id: str | None = None
    masked: str = ""
    code: str = ""

    def as_dict(self) -> dict:
        return {
            "state": self.state,
            "generation": self.generation,
            "authorize_url": self.authorize_url,
            "message": self.message,
            "account_id": self.account_id,
            "masked": self.masked,
            "code": self.code,
        }


class OrcaAuthManager:
    """Runs one authorization attempt at a time, with generation-safe state.

    Every terminal path — success, denial, exchange error, timeout, explicit
    cancel, switching auth method, unmount and ``pagehide`` — invalidates the
    attempt generation and shuts the listener down, so a late response can
    never overwrite a newer credential or leave the UI busy.
    """

    def __init__(
        self,
        store: CredentialStore,
        origins: Origins | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        receiver_factory=LoopbackReceiver,
        exchange=exchange_code,
        browser_open=None,
    ):
        self._store = store
        self._origins = origins or resolve_origins()
        self._timeout = timeout
        self._receiver_factory = receiver_factory
        self._exchange = exchange
        self._browser_open = browser_open or webbrowser.open
        self._lock = threading.RLock()
        self._generation = 0
        self._status = AuthStatus()
        self._receiver: LoopbackReceiver | None = None
        self._thread: threading.Thread | None = None
        self._store_generation = 0

    # -- public API --------------------------------------------------------
    def begin(self, open_browser: bool = True) -> dict:
        with self._lock:
            self._cancel_locked("cancelled", "A new authorization attempt replaced the previous one.")
            self._generation += 1
            generation = self._generation
            verifier = new_code_verifier()
            state = new_state()
            receiver = self._receiver_factory()
            redirect_uri = receiver.start(state)
            url = build_authorize_url(
                self._origins, redirect_uri, code_challenge(verifier), state
            )
            self._receiver = receiver
            self._store_generation = self._store.generation()
            self._status = AuthStatus(state="pending", generation=generation, authorize_url=url)

        if open_browser:
            threading.Thread(target=self._open_browser, args=(url,), daemon=True).start()

        self._thread = threading.Thread(
            target=self._run,
            args=(generation, receiver, verifier),
            daemon=True,
        )
        self._thread.start()
        return self._status.as_dict()

    def status(self, generation: int | None = None) -> dict:
        with self._lock:
            if generation is not None and generation != self._status.generation:
                return AuthStatus(state="stale", generation=generation).as_dict()
            return self._status.as_dict()

    def cancel(self, generation: int | None = None, pagehide: bool = False) -> dict:
        """Stop the current attempt. Safe to call from any thread and twice."""
        with self._lock:
            if generation is not None and generation != self._generation:
                # A stale caller cannot cancel a newer attempt.
                return self._status.as_dict()
            message = "Authorization cancelled." if not pagehide else "Authorization cancelled (page closed)."
            self._cancel_locked("cancelled", message)
            self._generation += 1
            self._status = AuthStatus(state="cancelled", generation=self._generation, message=message)
            return self._status.as_dict()

    def wait(self, timeout: float | None = None) -> dict:
        thread = self._thread
        if thread is not None:
            thread.join(timeout if timeout is not None else self._timeout + 10)
        return self.status()

    # -- internals ---------------------------------------------------------
    def _open_browser(self, url: str) -> None:
        try:
            self._browser_open(url, new=2)
        except Exception:
            pass  # the URL is shown in the UI as a fallback

    def _run(self, generation: int, receiver: LoopbackReceiver, verifier: str) -> None:
        try:
            code = receiver.wait(self._timeout)
            with self._lock:
                if generation != self._generation:
                    return  # superseded or cancelled
            result = self._exchange(self._origins, code, verifier)
            granted_scope = result.get("scope") or ""
            if granted_scope != "api":
                raise PkceError(
                    "scope_denied",
                    f'This key was granted scope "{granted_scope}", which does not permit inference. '
                    "Approve the api scope instead.",
                )
            with self._lock:
                if generation != self._generation:
                    return
                try:
                    credential = self._store.save_pkce_credential(
                        result["key"],
                        result.get("user_id"),
                        granted_scope,
                        expected_generation=self._store_generation,
                    )
                except CredentialError as exc:
                    raise PkceError("stale_result", str(exc)) from None
                self._status = AuthStatus(
                    state="success",
                    generation=generation,
                    authorize_url=self._status.authorize_url,
                    message=f"Connected to OrcaRouter ({credential.masked}).",
                    account_id=credential.account_id,
                    masked=credential.masked,
                )
        except PkceError as exc:
            self._finish_error(generation, exc.code, exc.message)
        except Exception:
            self._finish_error(generation, "unexpected_error", "Authorization failed unexpectedly.")
        finally:
            receiver.close()
            with self._lock:
                if self._receiver is receiver and generation == self._generation:
                    self._receiver = None

    def _finish_error(self, generation: int, code: str, message: str) -> None:
        with self._lock:
            if generation != self._generation:
                return
            self._generation += 1
            self._status = AuthStatus(
                state="error",
                generation=self._generation,
                authorize_url=self._status.authorize_url,
                message=redact(message),
                code=code,
            )

    def _cancel_locked(self, state: str, message: str) -> None:
        receiver = self._receiver
        self._receiver = None
        if receiver is not None:
            receiver.close()
        if self._status.state == "pending":
            self._status = AuthStatus(
                state=state,
                generation=self._generation,
                authorize_url=self._status.authorize_url,
                message=message,
            )
