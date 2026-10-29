import json
import os
import sys
import unittest

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wazuh_client import (  # noqa: E402
    WazuhError, alert_label, alert_to_inputs, build_query, fetch_alerts, normalize_alert, parse_alerts_file, parse_timestamp,
)

NESTED = {
    "timestamp": "2026-10-29T03:15:42.123+0000",
    "rule": {"id": "100210", "level": 10, "description": "Connection to known bad domain",
             "groups": ["web", "attack"], "mitre": {"id": ["T1071"], "technique": ["Application Layer Protocol"]}},
    "agent": {"id": "003", "name": "WS-014-INTERNAL", "ip": "10.20.1.15"},
    "decoder": {"name": "web-accesslog"},
    "location": "/var/log/secret-app.log",
    "full_log": "src=10.20.1.15 dst=203.0.113.9 url=hxxp://evil[.]example[.]com/a.php",
    "data": {"srcip": "10.20.1.15", "url": "http://evil.example.com/a.php"},
}


class FakeResp:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


def hits(*docs):
    return {"hits": {"hits": [{"_id": f"id{i}", "_source": d} for i, d in enumerate(docs)]}}


class NormalizeTests(unittest.TestCase):
    def test_nested(self):
        a = normalize_alert(NESTED)
        self.assertEqual((a["rule_id"], a["rule_level"], a["agent_name"]), ("100210", 10, "WS-014-INTERNAL"))
        self.assertEqual(a["mitre_ids"], ["T1071"])
        self.assertEqual(a["data"]["srcip"], "10.20.1.15")

    def test_flat_keys(self):
        a = normalize_alert({"rule.id": "5710", "rule.level": 5, "rule.description": "sshd: attempt", "agent.name": "web01"})
        self.assertEqual((a["rule_id"], a["rule_level"], a["agent_name"]), ("5710", 5, "web01"))

    def test_source_wrapper_and_id(self):
        a = normalize_alert({"_id": "abc", "_source": NESTED})
        self.assertEqual(a["id"], "abc")
        self.assertEqual(a["rule_id"], "100210")

    def test_missing_fields_do_not_crash(self):
        a = normalize_alert({})
        self.assertEqual((a["rule_id"], a["rule_level"], a["rule_groups"]), ("", None, []))

    def test_non_dict_rejected(self):
        with self.assertRaises(WazuhError):
            normalize_alert("text")

    def test_label(self):
        self.assertIn("L10", alert_label(normalize_alert(NESTED)))
        self.assertIn("rule 100210", alert_label(normalize_alert(NESTED)))


class InputsTests(unittest.TestCase):
    def setUp(self):
        self.inputs = alert_to_inputs(normalize_alert(NESTED))

    def test_name(self):
        self.assertEqual(self.inputs["alert_name"], "Connection to known bad domain (rule 100210)")

    def test_raw_text_has_iocs_for_extraction(self):
        from ioc_extract import extract_iocs
        values = {i["value"] for i in extract_iocs(self.inputs["raw_text"])}
        self.assertIn("evil.example.com", values)
        self.assertIn("203.0.113.9", values)

    def test_llm_facts_exclude_internal_identity(self):
        blob = "\n".join(self.inputs["llm_facts"])
        for secret in ("WS-014-INTERNAL", "10.20.1.15", "secret-app.log", "evil", "203.0.113.9"):
            self.assertNotIn(secret, blob)
        self.assertIn("Rule ID: 100210", blob)
        self.assertIn("MITRE ATT&CK IDs: T1071", blob)
        self.assertIn("Rule groups: web, attack", blob)

    def test_empty_fields_skipped(self):
        facts = alert_to_inputs(normalize_alert({"rule": {"id": "1"}}))["llm_facts"]
        self.assertEqual(facts, ["Rule ID: 1"])


class FetchTests(unittest.TestCase):
    def call(self, response, **kw):
        calls = []

        def post(url, **kwargs):
            calls.append((url, kwargs))
            if isinstance(response, Exception):
                raise response
            return response

        result = fetch_alerts(kw.pop("url", "https://10.0.0.5:9200/"), kw.pop("user", "admin"), kw.pop("pw", "secret"), post=post, **kw)
        return result, calls

    def test_success_and_request_shape(self):
        result, calls = self.call(FakeResp(200, hits(NESTED, NESTED)), size=10, min_level=8, hours=6, verify="/tmp/root-ca.pem")
        self.assertEqual(len(result), 2)
        url, kw = calls[0]
        self.assertEqual(url, "https://10.0.0.5:9200/wazuh-alerts-*/_search")
        self.assertEqual(kw["auth"], ("admin", "secret"))
        self.assertEqual(kw["verify"], "/tmp/root-ca.pem")
        body = kw["json"]
        self.assertEqual(body["size"], 10)
        self.assertEqual(body["query"]["bool"]["filter"][0]["range"]["rule.level"]["gte"], 8)
        self.assertEqual(body["query"]["bool"]["filter"][1]["range"]["timestamp"]["gte"], "now-6h")

    def test_query_string_added_only_when_given(self):
        self.assertNotIn("must", build_query()["query"]["bool"])
        self.assertEqual(build_query(query=" agent.name:web01 ")["query"]["bool"]["must"][0]["query_string"]["query"], "agent.name:web01")

    def test_http_errors_have_clear_messages(self):
        for code, text in ((401, "Kredensial ditolak"), (403, "izin"), (404, "port 55000"), (500, "HTTP 500")):
            with self.assertRaises(WazuhError) as ctx:
                self.call(FakeResp(code))
            self.assertIn(text, str(ctx.exception))

    def test_ssl_error_mentions_ca_and_never_password(self):
        with self.assertRaises(WazuhError) as ctx:
            self.call(requests.exceptions.SSLError("self signed certificate"))
        message = str(ctx.exception)
        self.assertIn("CERTIFICATE_VERIFY_FAILED", message)
        self.assertIn("Path CA", message)
        self.assertNotIn("secret", message)

    def test_connection_error(self):
        with self.assertRaises(WazuhError) as ctx:
            self.call(requests.exceptions.ConnectionError("refused"))
        self.assertIn("Tidak bisa menghubungi", str(ctx.exception))

    def test_unexpected_body(self):
        with self.assertRaises(WazuhError):
            self.call(FakeResp(200, {"message": "hi"}))
        with self.assertRaises(WazuhError):
            self.call(FakeResp(200, None))

    def test_input_validation(self):
        with self.assertRaises(WazuhError):
            self.call(FakeResp(200, hits()), url="ftp://x")
        with self.assertRaises(WazuhError):
            self.call(FakeResp(200, hits()), url="")
        with self.assertRaises(WazuhError):
            self.call(FakeResp(200, hits()), pw="")

    def test_empty_result_is_ok(self):
        result, _ = self.call(FakeResp(200, hits()))
        self.assertEqual(result, [])


class FileTests(unittest.TestCase):
    def test_ndjson(self):
        text = "\n".join(json.dumps(NESTED) for _ in range(3)) + "\n\nnot json\n"
        self.assertEqual(len(parse_alerts_file(text)), 3)

    def test_array_and_hits_and_single(self):
        self.assertEqual(len(parse_alerts_file(json.dumps([NESTED, NESTED]))), 2)
        self.assertEqual(len(parse_alerts_file(json.dumps(hits(NESTED)))), 1)
        self.assertEqual(len(parse_alerts_file(json.dumps(NESTED))), 1)

    def test_garbage(self):
        for text in ("", "   ", "hello\nworld", "[1, 2]"):
            with self.assertRaises(WazuhError):
                parse_alerts_file(text)


class TimestampTests(unittest.TestCase):
    def test_wazuh_format_with_offset(self):
        dt = parse_timestamp("2026-10-29T03:15:42.123+0000")
        self.assertEqual((dt.year, dt.hour, dt.minute, dt.second), (2026, 3, 15, 42))

    def test_offset_is_converted_to_utc(self):
        self.assertEqual(parse_timestamp("2026-10-29T10:00:00+0700").hour, 3)

    def test_z_and_naive(self):
        self.assertEqual(parse_timestamp("2026-10-29T03:00:00Z").hour, 3)
        self.assertEqual(parse_timestamp("2026-10-29T03:00:00").hour, 3)

    def test_garbage(self):
        for value in (None, "", "kemarin", "2026-13-45"):
            self.assertIsNone(parse_timestamp(value))


if __name__ == "__main__":
    unittest.main()
