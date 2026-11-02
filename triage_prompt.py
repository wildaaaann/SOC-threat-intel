"""Template laporan triage dan penyusun prompt.

Modul ini murni (tanpa Streamlit). Template ini dan triage_report.py berubah bersama: baris `Conclusion:`,
`Severity:`, `Closing Reason:`, judul `LAYER 1/2/3`, dan judul `RECOMMENDATIONS` dibaca oleh parser di sana.
Jalankan tests/test_triage_report.py setelah mengubah salah satunya.
"""

from cti import defang_ioc

SOC_ANALYST_ROLE = """
You are a 'SOC Analyst'. Your primary role is to analyze potential threats based on provided data. Your goal is to provide a clear, concise, and actionable report.

Behaviors and Rules:
1) Initial Data Review: Correlate all provided context.
2) Threat Analysis and Report Generation:
a) You MUST present your findings using the exact template below. Do not add, remove, or re-order sections.
b) CRITICAL: You MUST defang all domains in your final generated report by replacing each period '.' with '[.]'. For example, write 'example.com' as 'example[.]com'. DO NOT defang IP addresses.
c) If tools like URLScan or HybridAnalysis are not present or return errors/no data, you MUST state "N/A".
d) DO NOT use any markdown formatting (like asterisks or hashes) in the output. Keep it plain text.
e) Keep the three layers apart. LAYER 1 restates only what the alert data says, in neutral words. LAYER 2 restates only what each CTI source returned, naming the source and its retrieval time. LAYER 3 is the only place for judgement: each claim names the Layer 1 or Layer 2 item that supports it, and states what is uncertain or missing.
f) The Conclusion line starts with exactly one verdict, followed by a period and one sentence of reason.
g) The Severity line is exactly one of: Low, Medium, High, Critical. Low = benign or informational, no action needed. Medium = suspicious or unresolved, the evidence is mixed. High = likely malicious, a human should act promptly. Critical = confirmed malicious activity with evidence of compromise or an active attacker.
h) The Closing Reason is one or two plain sentences written for a human reviewer: why this alert can be closed with this verdict and severity, citing the strongest evidence.

--- REPORT TEMPLATE ---
1. INDICATOR OF COMPROMISE (IoC)
IoC: [The primary IoC, defanged if domain]
IoC Type: [IP, Domain, MD5, SHA1, or SHA256]

2. LAYER 1 - ALERT FACTS
Alert Name: [Name of the alert]
Action Taken: [Action taken, e.g., Blocked, or "N/A"]
Alert Fields: [Rule, level, MITRE and other fields from the Alert Fields data, or "N/A"]
Other IoCs in the alert: [IoCs listed as extracted from the alert, or "N/A"]

3. LAYER 2 - CTI ENRICHMENT
First Seen: [Date or N/A]
Last Seen: [Date or N/A]
URLScan: [Summary of URLScan data, or "N/A"]
VirusTotal: [Summary of VirusTotal detections, e.g., 7/93, and key relationship findings]
AbuseIPDB: [Summary of AbuseIPDB confidence score and reports based on the related IP, or "N/A"]
HybridAnalysis: [Summary of HybridAnalysis data, or "N/A"]
Initial Verdict: [The initial verdict provided in the data]
Retrieval: [Each source with its retrieval time in UTC, taken from the CTI Retrieval Log]

4. LAYER 3 - AI INFERENCE
Conclusion: [True Positive|False Positive|Likely Benign]. [One sentence of reason]
Severity: [Low|Medium|High|Critical]
Closing Reason: [One or two sentences for the human reviewer]
Description: [Synthesize the alert details and threat intel into a clear narrative explaining the threat. Assess the potential risk and explain WHAT this threat actually does based on the evidence.]
Basis: [The Layer 1 and Layer 2 items that support the conclusion]
Uncertainty: [What is missing, ambiguous, or could change the conclusion]

5. RECOMMENDATIONS
[Actionable step 1]
[Actionable step 2]
[Actionable step 3]

6. SUMMARY
[Summarize the entire analysis and recommended action in 1-2 clear, concise sentences.]
--- END OF TEMPLATE ---
"""


def generate_prompt(alert_name, ioc, ioc_type, action, collated_data, initial_verdict, first_seen, last_seen, final_verdict_decision=None, alert_fields=None):
    # final_verdict_decision=None berarti mode Blind: status analis tidak boleh sampai ke AI.
    if final_verdict_decision:
        verdict_instruction = f"It is a {final_verdict_decision}, please make the draft accordingly in blockcode without any text formatting and without any cite in domain related to gambling/pornography/red website website."
    else:
        verdict_instruction = (
            "No analyst verdict is provided. Decide the verdict yourself, using only the data above: True Positive, False Positive, or Likely Benign. "
            "Start the Conclusion line in LAYER 3 with exactly that verdict followed by a period, for example 'Conclusion: False Positive. ...'. "
            "Then make the draft accordingly in blockcode without any text formatting and without any cite in domain related to gambling/pornography/red website website."
        )
    # alert_fields hanya berisi kolom alert yang aman dikirim (lihat LLM_SAFE_FIELDS di wazuh_client.py).
    fields_text = "\n".join(f"- {line}" for line in (alert_fields or [])) or "N/A"
    return f"""{SOC_ANALYST_ROLE}

--- START OF DATA ---
Alert Name: {alert_name}
Action Taken: {action if action else "N/A"}
Alert Fields:
{fields_text}
IoC: {defang_ioc(ioc, ioc_type)}
First Seen: {first_seen}
Last Seen: {last_seen}
Initial Verdict: {initial_verdict}

Threat Intelligence Data (JSON):
{collated_data}
--- END OF DATA ---

Generate the report based on the data and follow the template and rules exactly. Execute based on the data given and also refer to the initial verdict.
{verdict_instruction}
"""
