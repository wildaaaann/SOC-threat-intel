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



from triage_report import (  # noqa: E402
    SEVERITIES, parse_closing_reason, parse_description, parse_field, parse_recommendations, parse_severity,
)

FULL = """1. INDICATOR OF COMPROMISE (IoC)
IoC: example[.]com

4. LAYER 3 - AI INFERENCE
Conclusion: False Positive. Reserved domain, zero detections.
Severity: Low
Closing Reason: Example.com is an RFC reserved domain.
It has zero detections on VirusTotal.
Description: Normal web access to a reference domain.
The traffic volume is small.
Basis: Layer 2 VirusTotal result.
Uncertainty: None.

5. RECOMMENDATIONS
Close the ticket.
Review the web filter rule.

6. SUMMARY
Close.
"""


class SeverityAndFieldTests(unittest.TestCase):
    def test_severity_each_value_and_case(self):
        for value in SEVERITIES:
            self.assertEqual(parse_severity(f"Severity: {value.lower()}"), value)

    def test_severity_markdown_and_brackets(self):
        self.assertEqual(parse_severity("**Severity:** High"), "High")
        self.assertEqual(parse_severity("Severity: [Critical] ok"), "Critical")

    def test_severity_template_echo_and_missing(self):
        self.assertEqual(parse_severity("Severity: [Low|Medium|High|Critical]"), UNREADABLE)
        self.assertEqual(parse_severity("Severity: Urgent"), UNREADABLE)
        self.assertEqual(parse_severity(""), UNREADABLE)
        self.assertEqual(parse_severity(None), UNREADABLE)

    def test_severity_word_in_prose_is_not_a_severity(self):
        self.assertEqual(parse_severity("The severity is high."), UNREADABLE)

    def test_closing_reason_multiline_stops_at_next_label(self):
        self.assertEqual(
            parse_closing_reason(FULL),
            "Example.com is an RFC reserved domain.\nIt has zero detections on VirusTotal.",
        )

    def test_description_multiline(self):
        self.assertEqual(parse_description(FULL), "Normal web access to a reference domain.\nThe traffic volume is small.")

    def test_field_missing_or_template_echo_is_empty(self):
        self.assertEqual(parse_closing_reason("Conclusion: True Positive."), "")
        self.assertEqual(parse_closing_reason("Closing Reason: [One or two sentences for the human reviewer]"), "")
        self.assertEqual(parse_field(None, "Description"), "")

    def test_recommendations_section(self):
        self.assertEqual(parse_recommendations(FULL), "Close the ticket.\nReview the web filter rule.")

    def test_recommendations_missing(self):
        self.assertEqual(parse_recommendations("4. LAYER 3 - AI INFERENCE\nConclusion: True Positive."), "")
        self.assertEqual(parse_recommendations(""), "")

    def test_conclusion_still_read_in_full_report(self):
        self.assertEqual(parse_ai_verdict(FULL), "False Positive")

    def test_layers_still_complete_with_new_lines(self):
        # Fakta dan pengayaan tidak ada di FULL: harus terdeteksi tidak lengkap, bukan error.
        self.assertFalse(layers_complete(FULL))

if __name__ == "__main__":
    unittest.main()
