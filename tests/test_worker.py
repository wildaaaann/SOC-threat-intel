import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cti  # noqa: E402
from ticket_policy import STATUS_CLOSED_AI, STATUS_NEEDS_HUMAN  # noqa: E402
from ticket_store import TicketStore, read_worker_state  # noqa: E402
from wazuh_client import WazuhError, normalize_alert  # noqa: E402
from worker import Config, load_config, process_alert, run_cycle  # noqa: E402

GOOD_REPORT = """1. INDICATOR OF COMPROMISE (IoC)
IoC: evil[.]example[.]net

2. LAYER 1 - ALERT FACTS
Alert Name: web access

3. LAYER 2 - CTI ENRICHMENT
VirusTotal: 0/80

4. LAYER 3 - AI INFERENCE
Conclusion: False Positive. No engine flags the domain.
Severity: Low
Closing Reason: Zero detections on VirusTotal and a single small request.
Description: Routine web access.
Basis: Layer 2 VirusTotal.
Uncertainty: None.

5. RECOMMENDATIONS
Close the ticket.

6. SUMMARY
Close.
"""


class Resp:
    def __init__(self, payload, status=200):
        self._p, self.status_code = payload, status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._p


def make_alert(doc_id, ts, text="GET http://evil.example.net/index.html from 10.1.1.5", agent="SECRET-HOST-01"):
    return normalize_alert({"_id": doc_id, "_source": {
        "timestamp": ts, "rule": {"id": "31101", "level": 8, "description": "Web server 400 error code"},
        "agent": {"name": agent, "ip": "10.0.0.9"}, "full_log": text, "decoder": {"name": "web-accesslog"}}})


def vt_get(url, **kw):
    if "virustotal.com" in url and "/domains/" in url and not url.rstrip("/").endswith(("resolutions", "communicating_files")):
        return Resp({"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 80}}}})
    return Resp({"data": []})


class FakeLLM:
    def __init__(self, text=GOOD_REPORT, status=200):
        self.text, self.status, self.bodies = text, status, []

    def __call__(self, url, **kw):
        self.bodies.append(json.dumps(kw.get("json")))
        return Resp({"choices": [{"message": {"content": self.text}}]}, self.status)


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.cfg = Config(
            indexer_url="https://localhost:9200", indexer_user="u", indexer_password="p",
            tickets_path=os.path.join(d, "tickets.jsonl"), state_path=os.path.join(d, "state.json"),
            keys={"vt": "k", "abuse": "", "urlscan": "", "hybrid": ""}, llm_extra={"Groq": {"key": "g", "model": ""}},
            max_per_cycle=20,
        )
        self.store = TicketStore(self.cfg.tickets_path)
        self.llm = FakeLLM()
        self.get_patch = mock.patch("requests.get", vt_get)
        self.get_patch.start()
        self.now = datetime(2026, 10, 30, 2, 0, 0, tzinfo=timezone.utc)
        self.process = lambda alert, cfg: process_alert(alert, cfg, post=self.llm)

    def tearDown(self):
        self.get_patch.stop()
        self.tmp.cleanup()

    def cycle(self, alerts, process=None, now=None):
        calls = []

        def fetch(*a, **kw):
            calls.append((a, kw))
            return [dict(x, raw=x["raw"]) for x in alerts]
        result = run_cycle(self.cfg, self.store, fetch=fetch, process=process or self.process, now=now or self.now)
        self.fetch_calls = calls
        return result

    def test_new_alert_becomes_closed_ticket_with_everything_filled(self):
        self.cycle([make_alert("a1", "2026-10-30T01:59:00.000+0000")])
        (t,) = self.store.all()
        self.assertEqual((t["id"], t["status"], t["ai_verdict"], t["severity"]), ("a1", STATUS_CLOSED_AI, "False Positive", "Low"))
        self.assertTrue(t["closing_reason"] and t["description"] and t["recommendations"])
        self.assertEqual((t["ioc"], t["llm_provider"], t["review_status"]), ("evil.example.net", "Groq", "Belum direview"))
        self.assertIn("domain", {e["type"] for e in t["entities"]})
        self.assertIn("host", {e["type"] for e in t["entities"]})

    def test_second_cycle_does_not_duplicate(self):
        alerts = [make_alert("a1", "2026-10-30T01:59:00.000+0000")]
        self.cycle(alerts)
        calls_before = len(self.llm.bodies)
        self.cycle(alerts)
        self.assertEqual(len(self.store.all()), 1)
        self.assertEqual(len(self.llm.bodies), calls_before)

    def test_privacy_agent_name_and_raw_log_never_reach_the_llm(self):
        self.cycle([make_alert("a1", "2026-10-30T01:59:00.000+0000", text="GET http://evil.example.net/index.html SECRET-LOG-LINE")])
        self.assertEqual(len(self.llm.bodies), 1)
        body = self.llm.bodies[0]
        self.assertNotIn("SECRET-HOST-01", body)
        self.assertNotIn("SECRET-LOG-LINE", body)
        self.assertNotIn("10.0.0.9", body)
        self.assertIn("evil", body)

    def test_blind_prompt_carries_no_analyst_verdict(self):
        self.cycle([make_alert("a1", "2026-10-30T01:59:00.000+0000")])
        self.assertIn("No analyst verdict is provided", self.llm.bodies[0])
        self.assertNotIn("It is a", self.llm.bodies[0])

    def test_alert_without_public_ioc_is_held_and_llm_not_called(self):
        self.cycle([make_alert("a2", "2026-10-30T01:59:00.000+0000", text="Failed login for user bob from 10.1.1.5")])
        (t,) = self.store.all()
        self.assertEqual(t["status"], STATUS_NEEDS_HUMAN)
        self.assertIn("Tidak bisa diperkaya", t["hold_reasons"][0])
        self.assertEqual(self.llm.bodies, [])

    def test_virustotal_failure_is_held(self):
        def failing(url, **kw):
            raise RuntimeError("429 quota exceeded")
        with mock.patch("requests.get", failing):
            self.cycle([make_alert("a3", "2026-10-30T01:59:00.000+0000")])
        (t,) = self.store.all()
        self.assertEqual(t["status"], STATUS_NEEDS_HUMAN)
        self.assertTrue(any("VirusTotal gagal" in h for h in t["hold_reasons"]))

    def test_incomplete_ai_report_is_held(self):
        self.llm = FakeLLM("Conclusion: False Positive. but nothing else")
        self.cycle([make_alert("a4", "2026-10-30T01:59:00.000+0000")])
        (t,) = self.store.all()
        self.assertEqual(t["status"], STATUS_NEEDS_HUMAN)

    def test_all_llm_down_is_held(self):
        self.llm = FakeLLM(status=500)
        self.cycle([make_alert("a5", "2026-10-30T01:59:00.000+0000")])
        (t,) = self.store.all()
        self.assertEqual(t["status"], STATUS_NEEDS_HUMAN)
        self.assertIn("Semua penyedia AI gagal", t["hold_reasons"])

    def test_unexpected_exception_does_not_lose_the_alert_or_stop_the_queue(self):
        def boom_first(alert, cfg):
            if alert["id"] == "bad":
                raise RuntimeError("kejutan")
            return self.process(alert, cfg)
        self.cycle([make_alert("bad", "2026-10-30T01:58:00.000+0000"), make_alert("good", "2026-10-30T01:59:00.000+0000")], process=boom_first)
        tickets = {t["id"]: t for t in self.store.all()}
        self.assertEqual(tickets["bad"]["status"], STATUS_NEEDS_HUMAN)
        self.assertIn("Galat tak terduga", tickets["bad"]["hold_reasons"][0])
        self.assertEqual(tickets["good"]["status"], STATUS_CLOSED_AI)

    def test_cursor_advances_and_heartbeat_written(self):
        self.cycle([make_alert("a1", "2026-10-30T01:59:00.000+0000")])
        state = read_worker_state(self.cfg.state_path)
        self.assertTrue(state["cursor_utc"].startswith("2026-10-30T01:59:00"))
        self.assertEqual((state["processed_last_cycle"], state["processed_total"], state["last_error"], state["backlog"]), (1, 1, "", False))
        self.assertEqual(state["last_cycle_utc"], "2026-10-30 02:00:00")

    def test_next_query_starts_before_cursor_by_overlap(self):
        self.cycle([make_alert("a1", "2026-10-30T01:59:00.000+0000")])
        self.cycle([], now=self.now + timedelta(seconds=60))
        since = self.fetch_calls[0][0][3]
        self.assertEqual(since, datetime(2026, 10, 30, 1, 59, 0, tzinfo=timezone.utc) - timedelta(seconds=self.cfg.overlap_s))

    def test_first_run_looks_back_only_lookback_minutes(self):
        self.cycle([])
        since = self.fetch_calls[0][0][3]
        self.assertEqual(since, self.now - timedelta(minutes=self.cfg.lookback_min) - timedelta(seconds=self.cfg.overlap_s))

    def test_backlog_stops_cursor_at_last_processed_alert(self):
        self.cfg.max_per_cycle = 2
        alerts = [make_alert(f"b{i}", f"2026-10-30T01:5{i}:00.000+0000") for i in range(5)]
        r = self.cycle(alerts)
        self.assertEqual((r["processed"], r["backlog"]), (2, True))
        self.assertTrue(read_worker_state(self.cfg.state_path)["cursor_utc"].startswith("2026-10-30T01:51:00"))
        r = self.cycle(alerts)
        self.assertEqual(r["processed"], 2)
        r = self.cycle(alerts)
        self.assertEqual((r["processed"], r["backlog"]), (1, False))
        self.assertEqual(len(self.store.all()), 5)

    def test_wazuh_failure_records_error_and_keeps_cursor(self):
        self.cycle([make_alert("a1", "2026-10-30T01:59:00.000+0000")])
        cursor = read_worker_state(self.cfg.state_path)["cursor_utc"]

        def down(*a, **kw):
            raise WazuhError("Tidak bisa menghubungi Wazuh Indexer: refused")
        r = run_cycle(self.cfg, self.store, fetch=down, process=self.process, now=self.now + timedelta(seconds=60))
        state = read_worker_state(self.cfg.state_path)
        self.assertEqual((r["processed"], state["cursor_utc"]), (0, cursor))
        self.assertIn("refused", state["last_error"])

    def test_cache_reuses_cti_for_same_ioc_and_keeps_original_time(self):
        self.cfg.cache = cti.CtiCache(None, 3600)
        calls = []

        def counting(url, **kw):
            calls.append(url)
            return vt_get(url, **kw)
        with mock.patch("requests.get", counting):
            self.cycle([make_alert("c1", "2026-10-30T01:58:00.000+0000"), make_alert("c2", "2026-10-30T01:59:00.000+0000")])
        self.assertEqual(len(calls), 3)  # domain + 2 relationships, hanya sekali untuk dua alert
        t1, t2 = self.store.all()
        row = [r for r in t2["cti_log"] if r["Sumber"] == "VirusTotal"][0]
        self.assertIn("[dari cache]", row["Temuan"])
        self.assertEqual(row["Waktu (UTC)"], [r for r in t1["cti_log"] if r["Sumber"] == "VirusTotal"][0]["Waktu (UTC)"])

    def test_failed_cti_is_not_cached(self):
        self.cfg.cache = cti.CtiCache(None, 3600)

        def failing(url, **kw):
            raise RuntimeError("boom")
        with mock.patch("requests.get", failing):
            self.cycle([make_alert("c1", "2026-10-30T01:58:00.000+0000")])
        self.assertIsNone(self.cfg.cache.get("VirusTotal", "evil.example.net"))


class ConfigTests(unittest.TestCase):
    BASE = {"WAZUH_INDEXER_URL": "https://127.0.0.1:9200", "WAZUH_USER": "u", "WAZUH_PASSWORD": "p", "VT_API_KEY": "v", "GROQ_API_KEY": "g"}

    def test_defaults(self):
        cfg = load_config(self.BASE)
        self.assertEqual((cfg.min_level, cfg.poll_seconds, cfg.verify, cfg.indexer_verify, cfg.llm_fallback), (7, 60, True, True, True))
        self.assertEqual(cfg.llm_extra["Groq"]["key"], "g")

    def test_missing_everything_is_listed_at_once(self):
        with self.assertRaises(ValueError) as ctx:
            load_config({})
        for name in ("WAZUH_INDEXER_URL", "WAZUH_USER", "WAZUH_PASSWORD", "VT_API_KEY", "minimal satu key AI"):
            self.assertIn(name, str(ctx.exception))

    def test_ca_path_and_tls_off_and_level(self):
        cfg = load_config(dict(self.BASE, WAZUH_CA="/x/root-ca.pem", WORKER_TLS_VERIFY="false", WORKER_MIN_LEVEL="10"))
        self.assertEqual((cfg.indexer_verify, cfg.verify, cfg.min_level), ("/x/root-ca.pem", False, 10))

    def test_gemini_alone_is_enough(self):
        env = {k: v for k, v in self.BASE.items() if k != "GROQ_API_KEY"}
        self.assertEqual(load_config(dict(env, GEMINI_API_KEY="x")).gemini_key, "x")


if __name__ == "__main__":
    unittest.main()
