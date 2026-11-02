import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ticket_policy import (PRIORITY_HUMAN, PRIORITY_MUST, PRIORITY_NORMAL, REVIEW_CONFIRMED, REVIEW_CORRECTED, REVIEW_PENDING,  # noqa: E402
                           STATUS_CLOSED_AI, STATUS_CLOSED_HUMAN, STATUS_NEEDS_HUMAN, build_ticket, decide, review_changes,
                           sort_for_review, summarize_tickets)
from ticket_store import TicketStore, read_worker_state, write_worker_state  # noqa: E402


def report(verdict="False Positive", severity="Low", reason="Reserved domain, zero detections.", recs="Close the ticket.", desc="Normal traffic."):
    return f"""1. INDICATOR OF COMPROMISE (IoC)
IoC: example[.]com

2. LAYER 1 - ALERT FACTS
Alert Name: test

3. LAYER 2 - CTI ENRICHMENT
VirusTotal: 0/90

4. LAYER 3 - AI INFERENCE
Conclusion: {verdict}. Because.
Severity: {severity}
Closing Reason: {reason}
Description: {desc}
Basis: Layer 2.
Uncertainty: None.

5. RECOMMENDATIONS
{recs}

6. SUMMARY
Done.
"""


def ctx_ok(vt_status="OK"):
    return {"ioc": "example.com", "ioc_type": "domain", "cti_log": [
        {"Sumber": "VirusTotal", "Query": "example.com", "Waktu (UTC)": "2026-10-30 01:00:00", "Status": vt_status, "Temuan": "x"},
        {"Sumber": "URLScan", "Query": "example.com", "Waktu (UTC)": "2026-10-30 01:00:01", "Status": "OK", "Temuan": "y"},
    ], "final_prompt": "PROMPT"}


def gen_for(text, provider="Gemini", layers=(True, True, True)):
    return {"report": text, "llm_used": {"provider": provider, "model": "m"}, "llm_fallback_used": False,
            "layers": dict(zip(("fakta", "pengayaan", "inferensi"), layers)), "layers_ok": all(layers)}


ALERT = {"id": "A1", "timestamp": "2026-10-30T01:00:00.000+0000", "rule_id": "5710", "rule_description": "desc", "rule_level": 8,
         "agent_name": "web01", "agent_ip": "10.0.0.5"}


class DecideTests(unittest.TestCase):
    def test_clean_benign_closes_with_normal_review(self):
        status, holds, priority, parsed = decide(ctx_ok(), gen_for(report()))
        self.assertEqual((status, holds, priority), (STATUS_CLOSED_AI, [], PRIORITY_NORMAL))
        self.assertEqual((parsed["verdict"], parsed["severity"]), ("False Positive", "Low"))
        self.assertTrue(parsed["closing_reason"] and parsed["recommendations"] and parsed["description"])

    def test_true_positive_is_closed_but_review_is_mandatory(self):
        status, _, priority, _ = decide(ctx_ok(), gen_for(report("True Positive", "High")))
        self.assertEqual((status, priority), (STATUS_CLOSED_AI, PRIORITY_MUST))

    def test_high_severity_benign_is_inconsistent_and_held(self):
        status, holds, priority, _ = decide(ctx_ok(), gen_for(report("False Positive", "Critical")))
        self.assertEqual((status, priority), (STATUS_NEEDS_HUMAN, PRIORITY_HUMAN))
        self.assertTrue(any("tidak konsisten" in h for h in holds))

    def test_true_positive_low_is_inconsistent(self):
        status, holds, _, _ = decide(ctx_ok(), gen_for(report("True Positive", "Low")))
        self.assertEqual(status, STATUS_NEEDS_HUMAN)
        self.assertTrue(any("tidak konsisten" in h for h in holds))

    def test_medium_severity_true_positive_and_benign_are_consistent(self):
        self.assertEqual(decide(ctx_ok(), gen_for(report("True Positive", "Medium")))[0], STATUS_CLOSED_AI)
        self.assertEqual(decide(ctx_ok(), gen_for(report("Likely Benign", "Medium")))[0], STATUS_CLOSED_AI)

    def test_unreadable_verdict_severity_reason_recs_description_each_hold(self):
        cases = {
            "Verdict AI tidak terbaca": report().replace("Conclusion: False Positive.", "Conclusion: Suspicious."),
            "Severity AI tidak terbaca": report(severity="Urgent"),
            "Alasan penutupan AI kosong": report(reason="[One or two sentences for the human reviewer]"),
            "Rekomendasi AI kosong": report(recs=""),
            "Deskripsi AI kosong": report(desc=""),
        }
        for message, text in cases.items():
            status, holds, _, _ = decide(ctx_ok(), gen_for(text))
            self.assertEqual(status, STATUS_NEEDS_HUMAN, message)
            self.assertTrue(any(message in h for h in holds), f"{message}: {holds}")

    def test_missing_layer_holds(self):
        status, holds, _, _ = decide(ctx_ok(), gen_for(report(), layers=(True, False, True)))
        self.assertEqual(status, STATUS_NEEDS_HUMAN)
        self.assertTrue(any("pengayaan" in h for h in holds))

    def test_virustotal_failure_holds_even_if_report_is_perfect(self):
        status, holds, _, _ = decide(ctx_ok(vt_status="Gagal"), gen_for(report()))
        self.assertEqual(status, STATUS_NEEDS_HUMAN)
        self.assertTrue(any("VirusTotal gagal" in h for h in holds))

    def test_no_successful_cti_source_holds(self):
        ctx = ctx_ok()
        ctx["cti_log"] = [{"Sumber": "VirusTotal", "Status": "Tidak ada data"}]
        status, holds, _, _ = decide(ctx, gen_for(report()))
        self.assertEqual(status, STATUS_NEEDS_HUMAN)
        self.assertTrue(any("Tidak ada sumber CTI" in h for h in holds))

    def test_all_llm_providers_failed_holds(self):
        status, holds, _, _ = decide(ctx_ok(), gen_for("Terjadi kesalahan", provider="-"))
        self.assertEqual(status, STATUS_NEEDS_HUMAN)
        self.assertIn("Semua penyedia AI gagal", holds)

    def test_enrich_error_holds_without_gen(self):
        status, holds, priority, parsed = decide({"error": "Alert Name dan Primary IoC wajib diisi"}, None)
        self.assertEqual((status, priority), (STATUS_NEEDS_HUMAN, PRIORITY_HUMAN))
        self.assertIn("Tidak bisa diperkaya", holds[0])

    def test_no_ioc_hold_message_describes_the_alert_not_the_manual_form(self):
        _, holds, _, _ = decide({"error": "Alert Name dan Primary IoC wajib diisi (atau tempel Raw Alert...)!"}, None)
        self.assertIn("Tidak ada IoC publik", holds[0])
        self.assertNotIn("Alert Name", holds[0])


class BuildAndReviewTests(unittest.TestCase):
    def closed(self, **kw):
        return build_ticket(ALERT, [{"type": "domain", "value": "example.com", "role": "Dari log", "public": None}],
                            ctx_ok(), gen_for(report(**kw)), tls_verify=True, processing_s=3.2)

    def test_ticket_fields(self):
        t = self.closed()
        self.assertEqual((t["id"], t["status"], t["review_status"], t["review_priority"]), ("A1", STATUS_CLOSED_AI, REVIEW_PENDING, PRIORITY_NORMAL))
        self.assertEqual((t["ai_verdict"], t["severity"], t["ioc"], t["llm_provider"], t["tls_verify"]), ("False Positive", "Low", "example.com", "Gemini", True))
        self.assertIsInstance(t["alert_to_close_s"], float)
        self.assertEqual(t["prompt"], "PROMPT")

    def test_held_ticket_has_no_alert_to_close(self):
        t = build_ticket(ALERT, [], {"error": "x"}, None, tls_verify=True, processing_s=0.1)
        self.assertEqual((t["status"], t["alert_to_close_s"], t["report"], t["llm_provider"]), (STATUS_NEEDS_HUMAN, None, "", None))

    def test_confirm_both(self):
        t = self.closed()
        c = review_changes(t, reviewer="R1", final_severity="Low", reason_ok=True)
        self.assertEqual((c["review_status"], c["severity_agree"], c["reason_agree"], c["final_reason"]), (REVIEW_CONFIRMED, True, True, t["closing_reason"]))

    def test_correct_severity_only(self):
        c = review_changes(self.closed(), reviewer="R1", final_severity="Medium", reason_ok=True)
        self.assertEqual((c["review_status"], c["severity_agree"], c["reason_agree"]), (REVIEW_CORRECTED, False, True))

    def test_correct_reason_requires_text(self):
        t = self.closed()
        with self.assertRaises(ValueError):
            review_changes(t, reviewer="R1", final_severity="Low", reason_ok=False)
        c = review_changes(t, reviewer="R1", final_severity="Low", reason_ok=False, corrected_reason="Alasan lain")
        self.assertEqual((c["reason_agree"], c["final_reason"]), (False, "Alasan lain"))

    def test_review_requires_reviewer_severity_and_reason_choice(self):
        t = self.closed()
        for kw in ({"reviewer": "", "final_severity": "Low", "reason_ok": True},
                   {"reviewer": "R1", "final_severity": None, "reason_ok": True},
                   {"reviewer": "R1", "final_severity": "Low", "reason_ok": None}):
            with self.assertRaises(ValueError):
                review_changes(t, **kw)

    def test_held_ticket_needs_verdict_severity_and_reason_and_becomes_closed_by_analyst(self):
        t = build_ticket(ALERT, [], {"error": "x"}, None, tls_verify=True, processing_s=0.1)
        with self.assertRaises(ValueError):
            review_changes(t, reviewer="R1", final_severity="Low", corrected_reason="r")
        with self.assertRaises(ValueError):
            review_changes(t, reviewer="R1", final_severity="Low", final_verdict="False Positive")
        c = review_changes(t, reviewer="R1", final_severity="Low", final_verdict="False Positive", corrected_reason="Benign host scan")
        self.assertEqual((c["status"], c["final_verdict"], c["severity_agree"]), (STATUS_CLOSED_HUMAN, "False Positive", None))


class ManualColumnTests(unittest.TestCase):
    def closed(self):
        return build_ticket(ALERT, [], ctx_ok(), gen_for(report(desc="Narasi AI.", recs="Rekomendasi AI.")), tls_verify=True, processing_s=1)

    def test_empty_manual_text_accepts_ai_text_and_records_agreement(self):
        c = review_changes(self.closed(), reviewer="R1", final_severity="Low", reason_ok=True)
        self.assertEqual((c["final_description"], c["final_recommendations"]), ("Narasi AI.", "Rekomendasi AI."))
        self.assertEqual((c["description_agree"], c["recommendations_agree"]), (True, True))

    def test_manual_text_replaces_ai_text_and_counts_as_disagreement(self):
        c = review_changes(self.closed(), reviewer="R1", final_severity="Low", reason_ok=True,
                           manual_description="Narasi analis.", manual_recommendations="Isolasi host.")
        self.assertEqual((c["final_description"], c["final_recommendations"]), ("Narasi analis.", "Isolasi host."))
        self.assertEqual((c["description_agree"], c["recommendations_agree"]), (False, False))

    def test_held_ticket_without_ai_text_has_no_agreement_value(self):
        t = build_ticket(ALERT, [], {"error": "x"}, None, tls_verify=True, processing_s=0.1)
        c = review_changes(t, reviewer="R1", final_severity="Low", final_verdict="False Positive", corrected_reason="r",
                           manual_description="Tulis sendiri.")
        self.assertEqual((c["final_description"], c["final_recommendations"]), ("Tulis sendiri.", ""))
        self.assertEqual((c["description_agree"], c["recommendations_agree"]), (None, None))

    def test_csv_has_ai_and_manual_columns_and_siem_entities(self):
        from ticket_store import tickets_to_csv
        t = build_ticket(ALERT, [{"type": "ip", "value": "8.8.8.8", "role": "Sumber", "field": "data.srcip", "public": True}],
                         ctx_ok(), gen_for(report(desc="Narasi AI.", recs="Rekomendasi AI.")), tls_verify=True, processing_s=1)
        t.update(review_changes(t, reviewer="R1", final_severity="Medium", reason_ok=True, manual_description="Narasi analis."))
        import csv, io
        row = next(csv.DictReader(io.StringIO(tickets_to_csv([t]))))
        self.assertEqual((row["description"], row["final_description"], row["final_severity"]), ("Narasi AI.", "Narasi analis.", "Medium"))
        self.assertEqual((row["recommendations"], row["final_recommendations"]), ("Rekomendasi AI.", "Rekomendasi AI."))
        self.assertEqual(row["entities"], "data.srcip=8.8.8.8")


class StoreAndSummaryTests(unittest.TestCase):
    def test_store_dedupes_ids_and_merges_review(self):
        with tempfile.TemporaryDirectory() as d:
            store = TicketStore(os.path.join(d, "tickets.jsonl"))
            t = build_ticket(ALERT, [], ctx_ok(), gen_for(report()), tls_verify=True, processing_s=1)
            store.append(t)
            store.append(dict(t, ai_verdict="True Positive"))  # id sama: diabaikan
            self.assertEqual(len(store.all()), 1)
            self.assertEqual(store.all()[0]["ai_verdict"], "False Positive")
            self.assertEqual(store.known_ids(), {"A1"})
            store.update("A1", review_changes(t, reviewer="R1", final_severity="Low", reason_ok=True))
            self.assertEqual(store.all()[0]["review_status"], REVIEW_CONFIRMED)
            self.assertEqual(len(store.all()), 1)

    def test_worker_state_roundtrip_and_missing(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sub", "state.json")
            self.assertEqual(read_worker_state(path), {})
            write_worker_state(path, {"cursor_utc": "x", "n": 2})
            self.assertEqual(read_worker_state(path), {"cursor_utc": "x", "n": 2})
            with open(path, "w") as h:
                h.write("{rusak")
            self.assertEqual(read_worker_state(path), {})

    def test_summary_counts_and_agreement(self):
        def tk(i, verdict, sev, review=None):
            t = build_ticket(dict(ALERT, id=f"T{i}"), [], ctx_ok(), gen_for(report(verdict, sev)), tls_verify=True, processing_s=1)
            if review:
                t.update(review_changes(t, reviewer="R", **review))
            return t
        tickets = [
            tk(1, "False Positive", "Low", dict(final_severity="Low", reason_ok=True)),
            tk(2, "False Positive", "Low", dict(final_severity="Medium", reason_ok=True)),
            tk(3, "True Positive", "High"),
            build_ticket(dict(ALERT, id="T4"), [], {"error": "x"}, None, tls_verify=True, processing_s=0),
        ]
        s = summarize_tickets(tickets)
        self.assertEqual((s["Tiket total"], s["Closed by AI"], s["Perlu manusia (tidak ditutup)"]), (4, 3, 1))
        self.assertEqual((s["True Positive yang ditutup AI"], s["Sudah direview"], s["Closed by AI belum direview"]), (1, 2, 1))
        self.assertEqual((s["Severity disetujui (%)"], s["Alasan disetujui (%)"]), (50.0, 100.0))

    def test_summary_empty(self):
        s = summarize_tickets([])
        self.assertEqual((s["Tiket total"], s["Severity disetujui (%)"], s["Alert ke tutup, median (detik)"]), (0, None, None))

    def test_sort_puts_human_then_mandatory_then_normal_and_reviewed_last(self):
        base = dict(review_status=REVIEW_PENDING, processed_at_utc="2026-10-30 01:00:00")
        tickets = [
            dict(base, id="normal", review_priority=PRIORITY_NORMAL),
            dict(base, id="must", review_priority=PRIORITY_MUST),
            dict(base, id="human", review_priority=PRIORITY_HUMAN),
            dict(base, id="done", review_priority=PRIORITY_HUMAN, review_status=REVIEW_CONFIRMED),
            dict(base, id="must-newer", review_priority=PRIORITY_MUST, processed_at_utc="2026-10-30 02:00:00"),
        ]
        self.assertEqual([t["id"] for t in sort_for_review(tickets)], ["human", "must-newer", "must", "normal", "done"])


if __name__ == "__main__":
    unittest.main()
