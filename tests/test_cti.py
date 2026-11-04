import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cti  # noqa: E402


class FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def urlscan_result(verdicts):
    return {"results": [{"result": "https://urlscan.io/result/x/", "verdicts": verdicts, "task": {"time": "2026-11-03T22:05:32.803Z"}}]}


class UrlscanTests(unittest.TestCase):
    def query(self, verdicts):
        with mock.patch("requests.get", lambda *a, **k: FakeResp(urlscan_result(verdicts))):
            return cti.query_urlscan("example.com", "domain", "key")

    def test_search_result_without_verdict_is_not_reported_as_ok_with_question_marks(self):
        raw = self.query({})
        status, finding = cti.summarize_cti("URLScan", raw)
        self.assertEqual(status, "Tidak ada data")
        self.assertIn("tanpa verdict", finding)
        self.assertNotIn("?", finding.split("(")[0])

    def test_llm_input_says_absence_of_verdict_is_not_evidence(self):
        note = json.loads(self.query({})).get("note", "")
        self.assertIn("not evidence", note)

    def test_verdict_present_is_reported_and_has_no_note(self):
        raw = self.query({"overall": {"malicious": False, "score": 0}})
        self.assertEqual(cti.summarize_cti("URLScan", raw), ("OK", "verdict overall malicious=False, score=0"))
        self.assertNotIn("note", json.loads(raw))

    def test_null_verdicts_do_not_crash(self):
        status, _ = cti.summarize_cti("URLScan", json.dumps({"verdicts": None, "task_time": None}))
        self.assertEqual(status, "Tidak ada data")


class SummaryTests(unittest.TestCase):
    def test_empty_result_is_skipped(self):
        self.assertEqual(cti.summarize_cti("HybridAnalysis", "")[0], "Dilewati")

    def test_error_is_failed(self):
        self.assertEqual(cti.summarize_cti("VirusTotal", '{"error": "403"}'), ("Gagal", "403"))

    def test_virustotal_counts(self):
        raw = json.dumps({"last_analysis_stats": {"malicious": 1, "harmless": 91}})
        self.assertEqual(cti.summarize_cti("VirusTotal", raw), ("OK", "malicious 1 dari 92 engine"))


if __name__ == "__main__":
    unittest.main()
