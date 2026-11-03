import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from llm_providers import GEMINI_MODEL, OPENAI_COMPATIBLE, LLMError, build_attempts, list_models, run_chain  # noqa: E402


class FakeResp:
    def __init__(self, status=200, payload=None, text=""):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.text = text

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
        self.assertEqual(attempts[0]["model"], OPENAI_COMPATIBLE["Groq"]["model"])
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
        post = make_post([FakeResp(500), FakeResp(500), RuntimeError("timeout"), RuntimeError("timeout")])
        text, used, log = run_chain("p", build_attempts("", EXTRA), None, post=post, retry_wait=0, sleep=lambda s: None)
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


class ModelAvailabilityTests(unittest.TestCase):
    def test_retired_model_404_and_410_say_how_to_fix_it(self):
        for code in (404, 410):
            post = make_post([FakeResp(code)])
            _, _, log = run_chain("p", build_attempts("", {"Groq": {"key": "k"}}), None, post=post)
            self.assertIn("tidak tersedia", log[0]["Detail"])
            self.assertIn("Cek model", log[0]["Detail"])
            self.assertIn(str(code), log[0]["Detail"])

    def test_router_model_actually_served_is_recorded(self):
        resp = FakeResp(200, {"model": "vendor/real-model:free", "choices": [{"message": {"content": "ok"}}]})
        text, used, log = run_chain("p", build_attempts("", {"OpenRouter": {"key": "k", "model": "openrouter/free"}}), None, post=make_post([resp]))
        self.assertEqual(used["model"], "openrouter/free -> vendor/real-model:free")
        self.assertEqual(log[0]["Model"], used["model"])

    def test_same_model_echoed_back_is_not_rewritten(self):
        resp = FakeResp(200, {"model": "openai/gpt-oss-120b", "choices": [{"message": {"content": "ok"}}]})
        _, used, _ = run_chain("p", build_attempts("", {"Groq": {"key": "k", "model": "openai/gpt-oss-120b"}}), None, post=make_post([resp]))
        self.assertEqual(used["model"], "openai/gpt-oss-120b")

    def test_gemini_model_default_and_override(self):
        self.assertEqual(build_attempts("g", {})[0]["model"], GEMINI_MODEL)
        self.assertEqual(build_attempts("g", {}, gemini_model=" gemini-x ")[0]["model"], "gemini-x")

    def test_list_models_sorted_and_openrouter_free_only(self):
        data = {"data": [{"id": "b/model"}, {"id": "a/model:free"}, {"id": "openrouter/free"}, {"id": "c/paid"}]}
        get = lambda url, **kw: FakeResp(200, data)
        self.assertEqual(list_models("Groq", "k", get=get), ["a/model:free", "b/model", "c/paid", "openrouter/free"])
        self.assertEqual(list_models("OpenRouter", "k", get=get), ["a/model:free", "openrouter/free"])

    def test_list_models_errors_never_contain_the_key(self):
        def boom(url, **kw):
            raise RuntimeError("connection failed for key SECRETKEY")
        with self.assertRaises(LLMError) as ctx:
            list_models("Groq", "SECRETKEY", get=boom)
        self.assertNotIn("SECRETKEY", str(ctx.exception))
        with self.assertRaises(LLMError) as ctx:
            list_models("Groq", "SECRETKEY", get=lambda url, **kw: FakeResp(401))
        self.assertIn("401", str(ctx.exception))
        with self.assertRaises(LLMError):
            list_models("Nope", "k")


class DiagnosticsAndRetryTests(unittest.TestCase):
    NO_WAIT = {"retry_wait": 0, "sleep": lambda s: None}

    def test_provider_error_message_is_shown_without_the_key(self):
        resp = FakeResp(400, {"error": {"message": "model requires terms acceptance"}})
        _, _, log = run_chain("p", build_attempts("", {"Groq": {"key": "SECRETKEY"}}), None, post=make_post([resp]), **self.NO_WAIT)
        self.assertIn("HTTP 400", log[0]["Detail"])
        self.assertIn("terms acceptance", log[0]["Detail"])
        self.assertNotIn("SECRETKEY", str(log))

    def test_error_without_json_falls_back_to_text(self):
        resp = FakeResp(400, text="plain failure")
        resp.json = lambda: (_ for _ in ()).throw(ValueError("no json"))
        _, _, log = run_chain("p", build_attempts("", {"Groq": {"key": "k"}}), None, post=make_post([resp]), **self.NO_WAIT)
        self.assertIn("plain failure", log[0]["Detail"])

    def test_gemini_503_is_retried_once_then_succeeds(self):
        calls = []

        def flaky(p, k, m):
            calls.append(m)
            if len(calls) == 1:
                raise RuntimeError("503 UNAVAILABLE. high demand")
            return "laporan"
        text, used, log = run_chain("p", build_attempts("gem", {}), flaky, **self.NO_WAIT)
        self.assertEqual((text, used["provider"], len(calls), log[0]["Status"]), ("laporan", "Gemini", 2, "OK"))
        self.assertIn("1x ulang", log[0]["Detail"])

    def test_persistent_503_falls_through_after_one_retry_only(self):
        calls = []

        def down(p, k, m):
            calls.append(1)
            raise RuntimeError("503 UNAVAILABLE")
        post = make_post([ok("dari groq")])
        text, used, log = run_chain("p", build_attempts("gem", {"Groq": {"key": "g"}}), down, post=post, **self.NO_WAIT)
        self.assertEqual((text, used["provider"], len(calls)), ("dari groq", "Groq", 2))
        self.assertIn("sudah diulang 1x", log[0]["Detail"])

    def test_permanent_errors_are_not_retried(self):
        for message in ("404 NOT_FOUND model gone", "API key ditolak (HTTP 401)", "HTTP 400: bad request"):
            calls = []

            def fail(p, k, m, message=message):
                calls.append(1)
                raise RuntimeError(message)
            run_chain("p", build_attempts("gem", {}), fail, **self.NO_WAIT)
            self.assertEqual(len(calls), 1, message)

    def test_http_503_from_openai_compatible_is_retried(self):
        post = make_post([FakeResp(503, {"error": {"message": "overloaded"}}), ok("pulih")])
        text, _, log = run_chain("p", build_attempts("", {"Groq": {"key": "g"}}), None, post=post, **self.NO_WAIT)
        self.assertEqual((text, len(post.calls)), ("pulih", 2))


if __name__ == "__main__":
    unittest.main()
