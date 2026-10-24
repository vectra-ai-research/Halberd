"""OpenAI-compatible client for the OrcaRouter relay.

OrcaRouter speaks the OpenAI wire format at ``{api_base}/chat/completions``.
Halberd's agent loop is written against Anthropic-style content blocks, so this
module translates in both directions and keeps the loop unchanged.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from .credentials import redact

DEFAULT_TIMEOUT = 120.0
MAX_ERROR_BYTES = 8 * 1024


class OrcaApiError(Exception):
    def __init__(self, code: str, message: str, status: int | None = None, needs_reauth: bool = False):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.needs_reauth = needs_reauth


class UnsupportedContent(ValueError):
    """A content block the OrcaRouter chat route cannot carry."""


@dataclass
class TextBlock:
    text: str
    type: str = "text"


@dataclass
class ToolUseBlock:
    id: str
    name: str
    input: dict
    type: str = "tool_use"


@dataclass
class AgentResponse:
    """Minimal Anthropic-shaped response for ``AttackAgent``'s tool loop."""

    content: list = field(default_factory=list)
    stop_reason: str = "end_turn"
    usage: dict = field(default_factory=dict)
    model: str = ""

    def __contains__(self, item):  # the loop probes ``"error" in response``
        return False


def to_openai_tools(tools) -> list[dict]:
    converted = []
    for tool in tools or []:
        if not isinstance(tool, dict) or not tool.get("name"):
            continue
        converted.append(
            {
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "parameters": tool.get("input_schema") or {"type": "object", "properties": {}},
                },
            }
        )
    return converted


def _image_part(block: dict) -> dict:
    source = block.get("source") or {}
    media_type = source.get("media_type") or "image/png"
    data = source.get("data") or ""
    return {"type": "image_url", "image_url": {"url": f"data:{media_type};base64,{data}"}}


def _text_of(blocks) -> str:
    parts = []
    for block in blocks:
        if isinstance(block, dict) and block.get("type") == "text":
            parts.append(block.get("text") or "")
    return "\n".join(part for part in parts if part)


def to_openai_messages(messages, system: str | None = None) -> list[dict]:
    """Translate Halberd/Anthropic-style messages into OpenAI chat messages."""
    converted: list[dict] = []
    if system:
        converted.append({"role": "system", "content": system})
    for message in messages or []:
        role = message.get("role")
        content = message.get("content")
        if role not in ("user", "assistant"):
            continue
        if isinstance(content, str):
            converted.append({"role": role, "content": content})
            continue
        if not isinstance(content, list):
            converted.append({"role": role, "content": str(content)})
            continue

        tool_uses = [b for b in content if isinstance(b, dict) and b.get("type") == "tool_use"]
        tool_results = [b for b in content if isinstance(b, dict) and b.get("type") == "tool_result"]

        if tool_uses:
            converted.append(
                {
                    "role": "assistant",
                    "content": _text_of(content) or None,
                    "tool_calls": [
                        {
                            "id": block.get("id") or "",
                            "type": "function",
                            "function": {
                                "name": block.get("name") or "",
                                "arguments": json.dumps(block.get("input") or {}),
                            },
                        }
                        for block in tool_uses
                    ],
                }
            )
        if tool_results:
            for block in tool_results:
                converted.append(
                    {
                        "role": "tool",
                        "tool_call_id": block.get("tool_use_id") or "",
                        "content": str(block.get("content") or ""),
                    }
                )
        if tool_uses or tool_results:
            # Any remaining text block in the same message rides along above.
            continue

        parts: list[dict] = []
        for block in content:
            if not isinstance(block, dict):
                continue
            kind = block.get("type")
            if kind == "text":
                parts.append({"type": "text", "text": block.get("text") or ""})
            elif kind == "image":
                parts.append(_image_part(block))
            elif kind == "document":
                raise UnsupportedContent(
                    "PDF/document attachments are not supported by the OrcaRouter chat route; "
                    "attach an image or use the Anthropic provider."
                )
        if not parts:
            continue
        if all(part.get("type") == "text" for part in parts):
            converted.append({"role": role, "content": "\n".join(p["text"] for p in parts)})
        else:
            converted.append({"role": role, "content": parts})
    return converted


def _map_finish_reason(reason: str | None) -> str:
    if reason == "tool_calls":
        return "tool_use"
    if reason == "length":
        return "max_tokens"
    return "end_turn"


def parse_completion(payload: dict, model: str = "") -> AgentResponse:
    choices = payload.get("choices") if isinstance(payload, dict) else None
    if not isinstance(choices, list) or not choices:
        raise OrcaApiError("invalid_response", "OrcaRouter returned no completion choices.")
    first = choices[0] if isinstance(choices[0], dict) else {}
    message = first.get("message") if isinstance(first.get("message"), dict) else {}
    blocks: list = []
    text = message.get("content")
    if isinstance(text, str) and text.strip():
        blocks.append(TextBlock(text=text))
    for call in message.get("tool_calls") or []:
        if not isinstance(call, dict):
            continue
        function = call.get("function") if isinstance(call.get("function"), dict) else {}
        raw_args = function.get("arguments")
        try:
            arguments = json.loads(raw_args) if isinstance(raw_args, str) and raw_args.strip() else {}
        except ValueError:
            arguments = {}
        if not isinstance(arguments, dict):
            arguments = {}
        blocks.append(
            ToolUseBlock(
                id=call.get("id") or "",
                name=function.get("name") or "",
                input=arguments,
            )
        )
    if not blocks:
        blocks.append(TextBlock(text=""))
    return AgentResponse(
        content=blocks,
        stop_reason=_map_finish_reason(first.get("finish_reason")),
        usage=payload.get("usage") or {},
        model=payload.get("model") or model,
    )


class OrcaRouterClient:
    """Thin OpenAI-compatible client bound to one API base and key."""

    def __init__(self, api_base: str, api_key: str, timeout: float = DEFAULT_TIMEOUT, opener=None):
        self.api_base = api_base.rstrip("/")
        self._api_key = api_key
        self.timeout = timeout
        self._open = opener or urllib.request.urlopen

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def chat(
        self,
        model: str,
        messages,
        max_tokens: int = 4096,
        tools=None,
        system: str | None = None,
    ) -> AgentResponse:
        body = {
            "model": model,
            "messages": to_openai_messages(messages, system),
            "max_tokens": max_tokens,
            "stream": False,
        }
        if tools:
            body["tools"] = to_openai_tools(tools)
        data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            self.api_base + "/chat/completions", data=data, headers=self._headers(), method="POST"
        )
        try:
            with self._open(request, timeout=self.timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            raise self._error_from(exc) from None
        except urllib.error.URLError as exc:
            raise OrcaApiError("network_error", f"Could not reach OrcaRouter: {exc.reason}") from None
        except TimeoutError:
            raise OrcaApiError("network_error", "The OrcaRouter request timed out.") from None
        try:
            payload = json.loads(raw.decode("utf-8"))
        except ValueError:
            raise OrcaApiError("invalid_response", "OrcaRouter returned an unreadable response.") from None
        if isinstance(payload, dict) and payload.get("error"):
            message = payload["error"]
            if isinstance(message, dict):
                message = message.get("message") or "OrcaRouter returned an error."
            raise OrcaApiError("api_error", redact(str(message))[:500])
        return parse_completion(payload, model)

    def _error_from(self, exc: urllib.error.HTTPError) -> OrcaApiError:
        status = exc.code
        try:
            detail = exc.read(MAX_ERROR_BYTES).decode("utf-8", "replace")
        except Exception:
            detail = ""
        message = detail
        try:
            parsed = json.loads(detail)
            if isinstance(parsed, dict):
                err = parsed.get("error")
                if isinstance(err, dict):
                    message = err.get("message") or detail
                elif isinstance(err, str):
                    message = err
        except ValueError:
            pass
        message = redact(str(message))[:500]
        if status == 401:
            return OrcaApiError(
                "unauthorized",
                "OrcaRouter rejected this key. Reconnect or paste a new key.",
                status=status,
                needs_reauth=True,
            )
        if status == 403:
            return OrcaApiError("forbidden", message or "This key cannot use that model.", status=status)
        if status == 429:
            return OrcaApiError("rate_limited", message or "OrcaRouter rate limit reached.", status=status)
        return OrcaApiError("api_error", message or f"OrcaRouter request failed ({status}).", status=status)

    def list_models(self) -> list[dict]:
        request = urllib.request.Request(
            self.api_base + "/models", headers=self._headers(), method="GET"
        )
        try:
            with self._open(request, timeout=self.timeout) as response:
                raw = response.read(512 * 1024)
        except urllib.error.HTTPError as exc:
            raise self._error_from(exc) from None
        except urllib.error.URLError as exc:
            raise OrcaApiError("network_error", f"Could not reach OrcaRouter: {exc.reason}") from None
        payload = json.loads(raw.decode("utf-8"))
        return payload.get("data", []) if isinstance(payload, dict) else []

    def __repr__(self) -> str:
        return f"OrcaRouterClient(api_base={self.api_base!r})"
