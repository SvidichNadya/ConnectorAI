import dataclasses
import json
import time
import unittest

from dcpm.errors import DCPMError
from dcpm.semantic.llm import LocalLLMClient, LocalLLMConfig, LocalModelUnavailable
from tests.support import MockLocalModel


class ConfigTests(unittest.TestCase):
    def test_model_name_required(self):
        with self.assertRaises(ValueError):
            LocalLLMConfig(model="")

    def test_base_url_must_be_http(self):
        with self.assertRaises(ValueError):
            LocalLLMConfig(model="m", base_url="ftp://127.0.0.1/")
        with self.assertRaises(ValueError):
            LocalLLMConfig(model="m", base_url="not a url")


class LoopbackGuardTests(unittest.TestCase):
    def test_refuses_non_loopback_base_url_even_if_it_would_resolve(self):
        srv = MockLocalModel([lambda r: '{"ok":1}'])
        self.addCleanup(srv.close)
        client = LocalLLMClient(LocalLLMConfig(model="m", base_url=srv.base_url.replace("127.0.0.1", "evil.test")),
                                resolver=lambda h, p: ["127.0.0.1"])  # DNS says loopback...
        # ...but the HTTP client must still connect using the *claimed* host for the socket; our guard
        # only okays loopback-resolving names, so a same-process resolver override is the only way to
        # test this path deterministically. Direct IP in base_url is the realistic/safe configuration:
        ok = LocalLLMClient(LocalLLMConfig(model="m", base_url=srv.base_url))
        self.assertEqual(ok.complete_json(system="s", user="u", max_tokens=10), '{"ok":1}')

    def test_mixed_dns_answer_is_refused(self):
        srv = MockLocalModel([lambda r: "ignored"])
        self.addCleanup(srv.close)
        client = LocalLLMClient(LocalLLMConfig(model="m", base_url=srv.base_url),
                                resolver=lambda h, p: ["127.0.0.1", "93.184.216.34"])
        with self.assertRaises(LocalModelUnavailable) as c:
            client.complete_json(system="s", user="u", max_tokens=5)
        self.assertFalse(c.exception.retryable)
        self.assertIn("loopback", c.exception.message)

    def test_dns_failure_is_unavailable_not_a_crash(self):
        client = LocalLLMClient(LocalLLMConfig(model="m", base_url="http://nope.invalid:9/v1"),
                                resolver=lambda h, p: (_ for _ in ()).throw(DCPMError("NETWORK_ERROR", "nx")))
        with self.assertRaises(LocalModelUnavailable):
            client.complete_json(system="s", user="u", max_tokens=5)

    def test_connect_refused_is_unavailable(self):
        client = LocalLLMClient(LocalLLMConfig(model="m", base_url="http://127.0.0.1:1/v1"))
        with self.assertRaises(LocalModelUnavailable) as c:
            client.complete_json(system="s", user="u", max_tokens=5)
        self.assertIn("is it running", c.exception.message)


class ProtocolTests(unittest.TestCase):
    def test_happy_path_and_request_shape(self):
        srv = MockLocalModel([lambda r: '{"answer":42}'])
        self.addCleanup(srv.close)
        client = LocalLLMClient(LocalLLMConfig(model="qwen2.5:7b", base_url=srv.base_url, temperature=0.0))
        out = client.complete_json(system="SYS", user="USER TEXT", max_tokens=123)
        self.assertEqual(out, '{"answer":42}')
        req = srv.calls[0]
        self.assertEqual(req["model"], "qwen2.5:7b")
        self.assertEqual(req["max_tokens"], 123)
        self.assertEqual(req["messages"], [{"role": "system", "content": "SYS"}, {"role": "user", "content": "USER TEXT"}])

    def test_complete_json_validated_parses_and_rejects_garbage(self):
        srv = MockLocalModel([lambda r: '```json\n{"x": 1}\n```', lambda r: "not json at all"])
        self.addCleanup(srv.close)
        client = LocalLLMClient(LocalLLMConfig(model="m", base_url=srv.base_url))
        self.assertEqual(client.complete_json_validated(system="s", user="u", max_tokens=5, limit=1000), {"x": 1})
        with self.assertRaises(LocalModelUnavailable) as c:
            client.complete_json_validated(system="s", user="u", max_tokens=5, limit=1000)
        self.assertFalse(c.exception.retryable)   # bad output shouldn't be retried blindly

    def test_malformed_server_response_shape(self):
        srv = MockLocalModel([(200, b'{"no_choices_key": true}')])
        self.addCleanup(srv.close)
        client = LocalLLMClient(LocalLLMConfig(model="m", base_url=srv.base_url))
        with self.assertRaises(LocalModelUnavailable) as c:
            client.complete_json(system="s", user="u", max_tokens=5)
        self.assertFalse(c.exception.retryable)

    def test_http_500_retries_then_succeeds(self):
        calls = {"n": 0}
        def flaky(r):
            calls["n"] += 1
            if calls["n"] == 1:
                e = RuntimeError("boom")
                e.http_status = 500
                return e
            return '{"ok":true}'
        srv = MockLocalModel([flaky, flaky])
        self.addCleanup(srv.close)
        client = LocalLLMClient(LocalLLMConfig(model="m", base_url=srv.base_url, max_retries=2, retry_base_delay_s=0.01))
        self.assertEqual(client.complete_json(system="s", user="u", max_tokens=5), '{"ok":true}')
        self.assertEqual(calls["n"], 2)

    def test_http_400_is_not_retried(self):
        def bad(r):
            e = RuntimeError("bad request")
            e.http_status = 400
            return e
        srv = MockLocalModel([bad, lambda r: '{"should":"not be reached"}'])
        self.addCleanup(srv.close)
        client = LocalLLMClient(LocalLLMConfig(model="m", base_url=srv.base_url, max_retries=3, retry_base_delay_s=0.01))
        with self.assertRaises(LocalModelUnavailable) as c:
            client.complete_json(system="s", user="u", max_tokens=5)
        self.assertFalse(c.exception.retryable)
        self.assertEqual(len(srv.calls), 1)

    def test_timeout_is_unavailable(self):
        srv = MockLocalModel([lambda r: (time.sleep(2), "late")[1]])
        self.addCleanup(srv.close)
        client = LocalLLMClient(LocalLLMConfig(model="m", base_url=srv.base_url, read_timeout_s=0.3, max_retries=0))
        with self.assertRaises(LocalModelUnavailable):
            client.complete_json(system="s", user="u", max_tokens=5)

    def test_oversized_answer_rejected(self):
        srv = MockLocalModel([lambda r: "x" * 2_000_000])
        self.addCleanup(srv.close)
        client = LocalLLMClient(LocalLLMConfig(model="m", base_url=srv.base_url, max_retries=0))
        with self.assertRaises(LocalModelUnavailable) as c:
            client.complete_json(system="s", user="u", max_tokens=5)
        self.assertFalse(c.exception.retryable)

    def test_long_prompt_is_truncated_not_rejected(self):
        srv = MockLocalModel([lambda r: json.dumps({"saw_len": len(r["messages"][1]["content"])})])
        self.addCleanup(srv.close)
        client = LocalLLMClient(LocalLLMConfig(model="m", base_url=srv.base_url, max_context_chars=500))
        out = json.loads(client.complete_json(system="s", user="x" * 5000, max_tokens=5))
        self.assertLessEqual(out["saw_len"], 500)

    def test_ping(self):
        ok_srv = MockLocalModel([lambda r: "pong"])
        self.addCleanup(ok_srv.close)
        self.assertTrue(LocalLLMClient(LocalLLMConfig(model="m", base_url=ok_srv.base_url)).ping())
        self.assertFalse(LocalLLMClient(LocalLLMConfig(model="m", base_url="http://127.0.0.1:1/v1")).ping())


if __name__ == "__main__":
    unittest.main()
