"""OpenAI-compatible client tests (translation, transport, error mapping)."""

from __future__ import annotations

import unittest

from core.orcarouter.client import (
    AgentResponse,
    OrcaApiError,
    OrcaRouterClient,
    TextBlock,
    ToolUseBlock,
    UnsupportedContent,
    parse_completion,
    to_openai_messages,
    to_openai_tools,
)

from tests.support import FAKE_KEY, FakeOrcaServer

TOOLS = [
    {
        "name": "execute_technique",
        "description": "Execute a technique",
        "input_schema": {"type": "object", "properties": {"t_id": {"type": "string"}}, "required": ["t_id"]},
        "cache_control": {"type": "ephemeral"},
    }
]


class TranslationTests(unittest.TestCase):
    def test_tools_are_converted_to_openai_functions(self):
        converted = to_openai_tools(TOOLS)
        self.assertEqual(converted[0]["type"], "function")
        self.assertEqual(converted[0]["function"]["name"], "execute_technique")
        self.assertEqual(converted[0]["function"]["parameters"], TOOLS[0]["input_schema"])
        self.assertNotIn("cache_control", converted[0]["function"])

    def test_system_message_is_prepended(self):
        messages = to_openai_messages([{"role": "user", "content": "hi"}], system="You are Halberd.")
        self.assertEqual(messages[0], {"role": "system", "content": "You are Halberd."})
        self.assertEqual(messages[1], {"role": "user", "content": "hi"})

    def test_image_blocks_become_data_urls(self):
        messages = to_openai_messages(
            [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "what is this"},
                        {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}},
                    ],
                }
            ]
        )
        parts = messages[0]["content"]
        self.assertEqual(parts[0], {"type": "text", "text": "what is this"})
        self.assertEqual(parts[1]["type"], "image_url")
        self.assertTrue(parts[1]["image_url"]["url"].startswith("data:image/png;base64,"))

    def test_documents_are_refused_not_silently_dropped(self):
        with self.assertRaises(UnsupportedContent):
            to_openai_messages(
                [
                    {
                        "role": "user",
                        "content": [
                            {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": "AAAA"}}
                        ],
                    }
                ]
            )

    def test_tool_use_and_tool_results_round_trip(self):
        messages = to_openai_messages(
            [
                {"role": "assistant", "content": [{"type": "tool_use", "id": "call-1", "name": "execute_technique", "input": {"t_id": "x"}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "call-1", "content": "done"}]},
            ]
        )
        self.assertEqual(messages[0]["role"], "assistant")
        self.assertEqual(messages[0]["tool_calls"][0]["id"], "call-1")
        self.assertEqual(messages[0]["tool_calls"][0]["function"]["name"], "execute_technique")
        self.assertEqual(messages[1], {"role": "tool", "tool_call_id": "call-1", "content": "done"})


class ParseTests(unittest.TestCase):
    def test_text_completion(self):
        response = parse_completion(
            {"choices": [{"finish_reason": "stop", "message": {"content": "hello"}}],
             "usage": {"total_tokens": 3}, "model": "orcarouter/auto"}
        )
        self.assertIsInstance(response, AgentResponse)
        self.assertIsInstance(response.content[0], TextBlock)
        self.assertEqual(response.content[0].text, "hello")
        self.assertEqual(response.stop_reason, "end_turn")
        self.assertNotIn("error", response)  # the agent loop's probe

    def test_tool_call_completion(self):
        response = parse_completion(
            {
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "content": None,
                            "tool_calls": [
                                {"id": "call-9", "type": "function",
                                 "function": {"name": "list_tactics", "arguments": '{"a": 1}'}}
                            ],
                        },
                    }
                ]
            }
        )
        self.assertEqual(response.stop_reason, "tool_use")
        block = response.content[0]
        self.assertIsInstance(block, ToolUseBlock)
        self.assertEqual(block.input, {"a": 1})
        self.assertEqual(block.name, "list_tactics")

    def test_malformed_arguments_fall_back_to_empty_dict(self):
        response = parse_completion(
            {"choices": [{"message": {"tool_calls": [{"id": "1", "function": {"name": "x", "arguments": "not json"}}]}}]}
        )
        self.assertEqual(response.content[0].input, {})

    def test_missing_choices_is_an_error(self):
        with self.assertRaises(OrcaApiError):
            parse_completion({"choices": []})


class TransportTests(unittest.TestCase):
    def test_chat_posts_to_the_api_origin_with_bearer_auth(self):
        with FakeOrcaServer() as server:
            client = OrcaRouterClient(server.api_base, FAKE_KEY)
            response = client.chat("orcarouter/auto", [{"role": "user", "content": "hi"}], tools=TOOLS)
            self.assertEqual(response.content[0].text, "ok")
            request = server.requests[-1]
            self.assertEqual(request["path"], "/v1/chat/completions")
            self.assertEqual(request["headers"]["authorization"], f"Bearer {FAKE_KEY}")
            self.assertEqual(request["body"]["model"], "orcarouter/auto")
            self.assertEqual(request["body"]["tools"][0]["function"]["name"], "execute_technique")

    def test_401_is_a_terminal_reauth_signal(self):
        with FakeOrcaServer(chat_status=401) as server:
            client = OrcaRouterClient(server.api_base, FAKE_KEY)
            with self.assertRaises(OrcaApiError) as ctx:
                client.chat("orcarouter/auto", [{"role": "user", "content": "hi"}])
            self.assertTrue(ctx.exception.needs_reauth)
            self.assertEqual(ctx.exception.code, "unauthorized")
            self.assertNotIn(FAKE_KEY, str(ctx.exception))

    def test_429_is_retryable(self):
        with FakeOrcaServer(chat_status=429) as server:
            client = OrcaRouterClient(server.api_base, FAKE_KEY)
            with self.assertRaises(OrcaApiError) as ctx:
                client.chat("orcarouter/auto", [{"role": "user", "content": "hi"}])
            self.assertEqual(ctx.exception.code, "rate_limited")
            self.assertFalse(ctx.exception.needs_reauth)

    def test_network_failure_is_reported(self):
        client = OrcaRouterClient("http://127.0.0.1:1/v1", FAKE_KEY, timeout=2)
        with self.assertRaises(OrcaApiError) as ctx:
            client.chat("orcarouter/auto", [{"role": "user", "content": "hi"}])
        self.assertEqual(ctx.exception.code, "network_error")

    def test_client_repr_has_no_secret(self):
        client = OrcaRouterClient("https://api.orcarouter.ai/v1", FAKE_KEY)
        self.assertNotIn(FAKE_KEY, repr(client))


if __name__ == "__main__":
    unittest.main()
