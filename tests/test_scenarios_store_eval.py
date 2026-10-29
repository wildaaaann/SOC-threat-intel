import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evaluation import (  # noqa: E402
    ai_is_correct, data_quality, format_rows, paired_comparison, score_decision, scored,
    summarize_conditions, summarize_models,
)
from scenarios import RESPONSE_ACTIONS, load_scenarios, parse_scenarios, validate_scenarios  # noqa: E402
from trial_store import CSV_FIELDS, TrialStore, trials_to_csv  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def good_scenario(**over):
    base = {
        "id": "S1", "title": "t", "alert_name": "a", "alert_text": "x", "primary_ioc": "example.com",
        "ground_truth": {"verdict": "False Positive", "correct_actions": [RESPONSE_ACTIONS[0]]},
    }
    base.update(over)
    return base


class ScenarioTests(unittest.TestCase):
    def test_shipped_file_is_valid(self):
        valid, errors = load_scenarios(os.path.join(REPO, "scenarios", "scenarios.json"))
        self.assertEqual(errors, [])
        self.assertGreaterEqual(len(valid), 3)
        self.assertTrue(all(not s["validated"] for s in valid), "contoh bawaan harus ditandai belum divalidasi")

    def test_valid_and_defaults(self):
        valid, errors = validate_scenarios([good_scenario()])
        self.assertEqual((len(valid), errors), (1, []))
        self.assertEqual(valid[0]["related_ip"], "")
        self.assertFalse(valid[0]["validated"])

    def test_problems_are_reported_not_raised(self):
        data = [
            good_scenario(id="A"),
            good_scenario(id="A"),                                   # id ganda
            good_scenario(id="B", primary_ioc=" "),                  # kolom kosong
            good_scenario(id="C", ground_truth={"verdict": "Maybe", "correct_actions": [RESPONSE_ACTIONS[0]]}),
            good_scenario(id="D", ground_truth={"verdict": "True Positive", "correct_actions": ["Teriak"]}),
            good_scenario(id="E", ground_truth={"verdict": "True Positive", "correct_actions": []}),
            "bukan objek",
        ]
        valid, errors = validate_scenarios(data)
        self.assertEqual([s["id"] for s in valid], ["A"])
        self.assertEqual(len(errors), 6)

    def test_not_a_list_and_bad_json(self):
        self.assertEqual(validate_scenarios({"id": "x"})[0], [])
        self.assertTrue(parse_scenarios("{oops")[1])
        self.assertTrue(load_scenarios("/nonexistent/file.json")[1])


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.store = TrialStore(os.path.join(self.dir.name, "sub", "trials.jsonl"))

    def tearDown(self):
        self.dir.cleanup()

    def test_missing_file_is_empty(self):
        self.assertEqual(self.store.all(), [])

    def test_append_adds_id_and_time_and_persists(self):
        saved = self.store.append({"participant": "P1", "mttr_s": 12.5})
        self.assertTrue(saved["id"] and saved["recorded_at_utc"])
        again = TrialStore(self.store.path).all()
        self.assertEqual(again[0]["participant"], "P1")

    def test_update_merges_and_unknown_id_is_false(self):
        trial = self.store.append({"participant": "P1"})
        self.assertTrue(self.store.update(trial["id"], {"rubric_evidence": 4, "rubric_rater": "R1"}))
        self.assertTrue(self.store.update(trial["id"], {"rubric_evidence": 5}))
        merged = self.store.get(trial["id"])
        self.assertEqual((merged["rubric_evidence"], merged["rubric_rater"]), (5, "R1"))
        self.assertFalse(self.store.update("nope", {"x": 1}))
        self.assertEqual(len(self.store.all()), 1)

    def test_corrupt_lines_are_skipped_and_counted(self):
        self.store.append({"participant": "P1"})
        with open(self.store.path, "a", encoding="utf8") as handle:
            handle.write("{broken\n[1,2]\n\n")
        self.assertEqual(len(self.store.all()), 1)
        self.assertEqual(self.store.skipped_lines, 2)

    def test_import_skips_known_ids_and_orphan_updates(self):
        first = self.store.append({"participant": "P1"})
        text = "\n".join([
            json.dumps({"id": first["id"], "participant": "DUP"}),
            json.dumps({"id": "new1", "participant": "P2"}),
            json.dumps({"_update": "new1", "changes": {"rubric_evidence": 3}}),
            json.dumps({"_update": "ghost", "changes": {"x": 1}}),
            "garbage",
        ])
        self.assertEqual(self.store.import_text(text), (1, 3))
        trials = {t["id"]: t for t in self.store.all()}
        self.assertEqual(trials[first["id"]]["participant"], "P1")
        self.assertEqual(trials["new1"]["rubric_evidence"], 3)

    def test_jsonl_roundtrip_into_fresh_store(self):
        t = self.store.append({"participant": "P1"})
        self.store.update(t["id"], {"rubric_evidence": 2})
        other = TrialStore(os.path.join(self.dir.name, "other.jsonl"))
        other.import_text(self.store.to_jsonl())
        self.assertEqual(other.all()[0]["rubric_evidence"], 2)

    def test_csv_has_fixed_header_and_flattens_lists(self):
        csv_text = trials_to_csv([{"id": "a", "correct_actions": ["x", "y"], "mttr_s": 3.2, "report": "SECRET LONG TEXT"}])
        header, row = csv_text.splitlines()
        self.assertEqual(header.split(","), CSV_FIELDS)
        self.assertIn("x; y", row)
        self.assertNotIn("SECRET", csv_text)


def trial(condition, participant="P1", scenario="S1", mttr=60.0, verdict_ok=True, action_ok=True, **extra):
    row = {
        "id": f"{condition}-{participant}-{scenario}", "condition": condition, "participant": participant,
        "scenario_id": scenario, "ground_truth_verdict": "True Positive", "mttr_s": mttr,
        "verdict_correct": verdict_ok, "action_correct": action_ok,
    }
    row.update(extra)
    return row


class EvaluationTests(unittest.TestCase):
    def test_score_decision(self):
        truth = {"verdict": "True Positive", "correct_actions": ["Isolasi perangkat"]}
        self.assertEqual(score_decision("True Positive", "Isolasi perangkat", truth), (True, True))
        self.assertEqual(score_decision("False Positive", "Isolasi perangkat", truth), (False, True))
        self.assertEqual(score_decision("True Positive", "Pantau / tunggu data tambahan", truth), (True, False))
        self.assertEqual(score_decision("True Positive", "x", None), (None, None))

    def test_ai_correct_counts_unreadable_as_wrong(self):
        truth = {"verdict": "True Positive", "correct_actions": []}
        self.assertTrue(ai_is_correct("True Positive", truth))
        self.assertFalse(ai_is_correct("Tidak terbaca", truth))
        self.assertIsNone(ai_is_correct("True Positive", None))

    def test_only_keyed_scenario_trials_are_scored(self):
        data = [trial("manual"), {"id": "adhoc", "condition": "platform", "mttr_s": 5}, trial("platform", scenario=None)]
        self.assertEqual([t["id"] for t in scored(data)], ["manual-P1-S1"])

    def test_condition_summary(self):
        data = [
            trial("manual", mttr=100, verdict_ok=True), trial("manual", participant="P2", mttr=200, verdict_ok=False),
            trial("platform", mttr=40, rubric_evidence=4, rubric_recommendation=5),
            trial("platform", participant="P2", mttr=60, rubric_evidence=2, rubric_recommendation=3),
        ]
        manual, platform = summarize_conditions(data)
        self.assertEqual((manual["n trial"], manual["n analis"], manual["MTTR median (s)"]), (2, 2, 150))
        self.assertEqual(manual["Verdict benar (%)"], 50.0)
        self.assertEqual(platform["MTTR rata-rata (s)"], 50)
        self.assertEqual((platform["Rubrik bukti (rata-rata)"], platform["n dinilai rubrik"]), (3, 2))
        self.assertIsNone(manual["Rubrik bukti (rata-rata)"])

    def test_empty_input_does_not_crash(self):
        manual, platform = summarize_conditions([])
        self.assertEqual((manual["n trial"], manual["MTTR median (s)"]), (0, None))
        self.assertEqual(summarize_models([]), [])
        self.assertEqual(paired_comparison([])["n pasangan"], 0)
        self.assertEqual(format_rows([manual])[0]["MTTR median (s)"], "n/a")

    def test_single_trial_quartiles(self):
        manual, _ = summarize_conditions([trial("manual", mttr=42)])
        self.assertEqual((manual["MTTR median (s)"], manual["MTTR Q1 (s)"], manual["MTTR Q3 (s)"]), (42, 42, 42))

    def test_models_are_never_pooled(self):
        data = [
            trial("platform", llm_provider="Gemini", llm_model="g", ai_correct=True, ai_verdict="True Positive", report_layers_ok=True, system_latency_s=8),
            trial("platform", participant="P2", llm_provider="Groq", llm_model="l", ai_correct=False, ai_verdict="Tidak terbaca", report_layers_ok=False, system_latency_s=4),
            trial("manual"),
        ]
        rows = summarize_models(data)
        self.assertEqual([(r["Penyedia"], r["n trial"]) for r in rows], [("Gemini", 1), ("Groq", 1)])
        groq = rows[1]
        self.assertEqual((groq["Verdict AI benar (%)"], groq["Verdict AI tidak terbaca (%)"], groq["Format 3 lapis lengkap (%)"]), (0.0, 100.0, 0.0))

    def test_paired_comparison(self):
        data = [
            trial("manual", "P1", "S1", 100), trial("platform", "P1", "S1", 40),
            trial("manual", "P2", "S1", 80), trial("platform", "P2", "S1", 90),
            trial("platform", "P3", "S1", 10),  # tanpa pasangan manual
        ]
        result = paired_comparison(data)
        self.assertEqual(result["n pasangan"], 2)
        self.assertEqual(result["selisih median (s)"], -25)
        self.assertEqual(result["pasangan platform lebih cepat"], 1)

    def test_data_quality_flags(self):
        data = [
            trial("platform", llm_fallback_used=True, tls_verify=False, analysis_mode="Dibantu: status analis dikirim ke AI"),
            trial("platform", participant="P2", llm_fallback_used=False, tls_verify=True, analysis_mode="Blind: AI menilai sendiri", rubric_evidence=3),
            {"id": "adhoc", "condition": "platform"},
        ]
        q = data_quality(data)
        self.assertEqual(q["platform memakai penyedia cadangan"], 1)
        self.assertEqual(q["platform dengan verifikasi SSL mati"], 1)
        self.assertEqual(q["platform mode Dibantu (status bocor ke AI)"], 1)
        self.assertEqual(q["belum dinilai rubrik"], 1)
        self.assertEqual(q["trial ad hoc (tanpa kunci jawaban, tidak dihitung)"], 1)


if __name__ == "__main__":
    unittest.main()
