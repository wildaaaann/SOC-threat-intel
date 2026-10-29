import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from triage_report import UNREADABLE, layers_complete, layers_status, parse_ai_verdict, parse_layers  # noqa: E402

GOOD = """1. INDICATOR OF COMPROMISE (IoC)
IoC: evil[.]example[.]com
IoC Type: Domain

2. LAYER 1 - ALERT FACTS
Alert Name: FGT utm:webfilter blocked
Action Taken: Blocked

3. LAYER 2 - CTI ENRICHMENT
VirusTotal: 12/92 malicious (retrieved 2026-10-29 03:00:00 UTC)
AbuseIPDB: N/A

4. LAYER 3 - AI INFERENCE
Conclusion: True Positive. Domain is flagged by 12 engines.
Reasoning: Layer 2 shows detections.

5. RECOMMENDATIONS
Block the domain.

6. SUMMARY
Block it.
"""


class VerdictTests(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(parse_ai_verdict(GOOD), "True Positive")

    def test_each_verdict_and_case(self):
        self.assertEqual(parse_ai_verdict("conclusion: false positive. x"), "False Positive")
        self.assertEqual(parse_ai_verdict("CONCLUSION: LIKELY BENIGN."), "Likely Benign")

    def test_markdown_and_quotes(self):
        self.assertEqual(parse_ai_verdict("**Conclusion:** False Positive."), "False Positive")
        self.assertEqual(parse_ai_verdict("Conclusion: [Likely Benign] ok"), "Likely Benign")
        self.assertEqual(parse_ai_verdict('Conclusion: "True Positive"'), "True Positive")

    def test_dash_separator(self):
        self.assertEqual(parse_ai_verdict("Conclusion - False Positive"), "False Positive")

    def test_template_echo_is_not_a_verdict(self):
        self.assertEqual(parse_ai_verdict("Conclusion: [True Positive|False Positive|Likely Benign]"), UNREADABLE)
        self.assertEqual(parse_ai_verdict("Conclusion: True Positive | False Positive"), UNREADABLE)

    def test_first_word_wins_over_later_mentions(self):
        self.assertEqual(parse_ai_verdict("Conclusion: Likely Benign. Not a True Positive."), "Likely Benign")

    def test_missing_or_other_words(self):
        self.assertEqual(parse_ai_verdict(""), UNREADABLE)
        self.assertEqual(parse_ai_verdict(None), UNREADABLE)
        self.assertEqual(parse_ai_verdict("Conclusion: Suspicious."), UNREADABLE)
        self.assertEqual(parse_ai_verdict("The verdict is True Positive"), UNREADABLE)
        self.assertEqual(parse_ai_verdict("Conclusion: True Positives were found"), UNREADABLE)


class LayerTests(unittest.TestCase):
    def test_complete_report(self):
        layers = parse_layers(GOOD)
        self.assertIn("Alert Name", layers["fakta"])
        self.assertIn("VirusTotal", layers["pengayaan"])
        self.assertIn("Conclusion", layers["inferensi"])
        self.assertNotIn("RECOMMENDATIONS", layers["inferensi"])
        self.assertTrue(layers_complete(GOOD))

    def test_layers_do_not_leak_into_each_other(self):
        layers = parse_layers(GOOD)
        self.assertNotIn("VirusTotal", layers["fakta"])
        self.assertNotIn("Conclusion", layers["pengayaan"])

    def test_missing_layer(self):
        text = GOOD.replace("3. LAYER 2 - CTI ENRICHMENT", "3. THREAT ANALYSIS")
        status = layers_status(text)
        self.assertEqual(status, {"fakta": True, "pengayaan": False, "inferensi": True})
        self.assertFalse(layers_complete(text))

    def test_empty_layer_counts_as_missing(self):
        text = "2. LAYER 1 - ALERT FACTS\n\n3. LAYER 2 - CTI ENRICHMENT\nx\n4. LAYER 3 - AI INFERENCE\ny\n"
        self.assertEqual(layers_status(text), {"fakta": False, "pengayaan": True, "inferensi": True})

    def test_last_layer_runs_to_end(self):
        text = "4. LAYER 3 - AI INFERENCE\nConclusion: False Positive.\nmore"
        self.assertIn("more", parse_layers(text)["inferensi"])

    def test_plain_text_without_numbers(self):
        self.assertFalse(layers_complete("just a paragraph"))
        self.assertFalse(layers_complete(""))
        self.assertFalse(layers_complete(None))

    def test_old_template_is_not_complete(self):
        old = "3. THREAT ANALYSIS\nConclusion: True Positive.\n4. DESCRIPTION\nx\n"
        self.assertFalse(layers_complete(old))
        self.assertEqual(parse_ai_verdict(old), "True Positive")

    def test_heading_variants(self):
        text = "2) Layer 1 - alert facts\na\n3) LAYER 2: CTI\nb\n4) **LAYER 3** inference\nc\n"
        self.assertTrue(layers_complete(text))


if __name__ == "__main__":
    unittest.main()
