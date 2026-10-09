import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from llm_providers import build_attempts, run_chain  # noqa: E402


class FakeResp:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload if payload is not None else {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


def ok(text):
    return FakeResp(200, {"choices": [{"message": {"content": text}}]})


def make_post(responses):
    calls = []

    def post(url, **kw):
        calls.append((url, kw))
        item = responses[len([c for c in calls]) - 1]
        if isinstance(item, Exception):
            raise item
        return item

    post.calls = calls
    return post


EXTRA = {
    "Groq": {"key": "g", "model": ""},
    "OpenRouter": {"key": "o", "model": "x/y:free"},
}


class ChainTests(unittest.TestCase):
    def test_order_and_skips_missing_keys(self):
        names = [a["provider"] for a in build_attempts("gem", EXTRA)]
        self.assertEqual(names, ["Gemini", "Groq", "OpenRouter"])

    def test_model_default_and_override(self):
        attempts = build_attempts("", EXTRA)
        self.assertEqual(attempts[0]["model"], "llama-3.3-70b-versatile")
        self.assertEqual(attempts[1]["model"], "x/y:free")

    def test_no_fallback_keeps_first_only(self):
        self.assertEqual(len(build_attempts("gem", EXTRA, fallback=False)), 1)

    def test_no_keys_means_no_attempts(self):
        self.assertEqual(build_attempts("", {}), [])

    def test_gemini_ok_stops_chain(self):
        post = make_post([])
        text, used, log = run_chain("p", build_attempts("gem", EXTRA), lambda p, k, m: "laporan", post=post)
        self.assertEqual((text, used["provider"], len(log), len(post.calls)), ("laporan", "Gemini", 1, 0))

    def test_gemini_429_falls_back_to_groq(self):
        def boom(p, k, m):
            raise RuntimeError("429 RESOURCE_EXHAUSTED")
        post = make_post([ok("dari groq")])
        text, used, log = run_chain("p", build_attempts("gem", EXTRA), boom, post=post)
        self.assertEqual((text, used["provider"]), ("dari groq", "Groq"))
        self.assertEqual([r["Status"] for r in log], ["Gagal", "OK"])
        self.assertIn("429", log[0]["Detail"])

    def test_http_429_and_empty_and_think_tags(self):
        post = make_post([FakeResp(429), ok("   "), ok("<think>x</think>\nhasil")])
        extra = {"Groq": {"key": "g"}, "OpenRouter": {"key": "o"}, "NVIDIA NIM": {"key": "n"}}
        text, used, log = run_chain("p", build_attempts("", extra), None, post=post)
        self.assertEqual(text, "hasil")
        self.assertEqual([r["Status"] for r in log], ["Gagal", "Gagal", "OK"])

    def test_auth_error_is_reported_without_key(self):
        post = make_post([FakeResp(401)])
        _, _, log = run_chain("p", build_attempts("", {"Groq": {"key": "SECRETKEY"}}), None, post=post)
        self.assertIn("401", log[0]["Detail"])
        self.assertNotIn("SECRETKEY", str(log))

    def test_all_fail_returns_none_with_full_log(self):
        post = make_post([FakeResp(500), RuntimeError("timeout")])
        text, used, log = run_chain("p", build_attempts("", EXTRA), None, post=post)
        self.assertIsNone(text)
        self.assertIsNone(used)
        self.assertEqual(len(log), 2)

    def test_verify_flag_and_bearer_passed(self):
        post = make_post([ok("a")])
        run_chain("p", build_attempts("", {"Groq": {"key": "k"}}), None, verify=False, post=post)
        url, kw = post.calls[0]
        self.assertEqual(url, "https://api.groq.com/openai/v1/chat/completions")
        self.assertIs(kw["verify"], False)
        self.assertEqual(kw["headers"]["Authorization"], "Bearer k")


if __name__ == "__main__":
    unittest.main()
