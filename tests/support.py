"""Shared test doubles: a loopback HTTP server that plays the OrcaRouter side.

Every credential used here is a fake literal. No real key, verifier or code is
ever written to a fixture.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FAKE_KEY = "sk-orca-TESTKEY0000000000000000"
FAKE_ACCOUNT = "user-42"


class FakeOrcaServer:
    """A tiny HTTP server for the auth exchange, catalog and chat routes."""

    def __init__(self, exchange_status: int = 200, exchange_body: dict | None = None,
                 catalog_body=None, chat_body=None, headers=None,
                 chat_status: int = 200, catalog_status: int = 200):
        self.requests: list[dict] = []
        self.exchange_status = exchange_status
        self.exchange_body = exchange_body if exchange_body is not None else {
            "key": FAKE_KEY, "user_id": FAKE_ACCOUNT, "scope": "api"
        }
        self.catalog_body = catalog_body
        self.chat_body = chat_body
        self.chat_status = chat_status
        self.catalog_status = catalog_status
        self.extra_headers = headers or {}
        self._server = None
        self._thread = None
        self.port = None

    def __enter__(self):
        server = self
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):
                return

            def _record(self, method):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                try:
                    body = json.loads(raw.decode("utf-8")) if raw else None
                except ValueError:
                    body = raw.decode("utf-8", "replace")
                server.requests.append(
                    {
                        "method": method,
                        "path": self.path,
                        "headers": {k.lower(): v for k, v in self.headers.items()},
                        "body": body,
                    }
                )
                return body

            def _send(self, status, payload):
                data = json.dumps(payload).encode("utf-8") if payload is not None else b""
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Connection", "close")
                for key, value in outer.extra_headers.items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):  # noqa: N802
                self._record("POST")
                if self.path.startswith("/api/v1/auth/keys"):
                    status = outer.exchange_status
                    body = outer.exchange_body if 200 <= status < 300 else {"error": "invalid_grant"}
                    self._send(status, body)
                    return
                if self.path.startswith("/v1/chat/completions"):
                    if outer.chat_status >= 400:
                        self._send(outer.chat_status, {"error": {"message": "test upstream error"}})
                    else:
                        self._send(200, outer.chat_body or _default_chat())
                    return
                self._send(404, {"error": "not found"})

            def do_GET(self):  # noqa: N802
                self._record("GET")
                if self.path.startswith("/v1/models"):
                    if outer.catalog_status >= 400:
                        self._send(outer.catalog_status, {"error": "test"})
                    else:
                        self._send(200, outer.catalog_body if outer.catalog_body is not None else _default_catalog())
                    return
                self._send(404, {"error": "not found"})

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        if self._thread:
            self._thread.join(timeout=2)

    @property
    def auth_base(self):
        return f"http://127.0.0.1:{self.port}"

    @property
    def api_base(self):
        return f"http://127.0.0.1:{self.port}/v1"

    def paths(self):
        return [request["path"] for request in self.requests]


def _default_chat():
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "model": "orcarouter/auto",
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": "ok"},
            }
        ],
        "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4},
    }


def _default_catalog():
    return {
        "object": "list",
        "success": True,
        "data": [
            {"id": "orcarouter/auto", "supported_endpoint_types": ["openai", "anthropic"]},
            {
                "id": "openai/gpt-5.5",
                "supported_endpoint_types": ["openai", "openai-response"],
                "architecture": {"input_modalities": ["text", "image"]},
                "context_length": 400000,
            },
            {
                "id": "deepseek/deepseek-v4-pro",
                "supported_endpoint_types": ["openai"],
                "architecture": {"input_modalities": ["text"]},
            },
        ],
    }
