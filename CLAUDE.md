# SOC Threat Intel

Streamlit prototype for the skripsi "Wazuh + CTI + generative AI incident triage". Bab 1 flow: alert, CTI enrichment, Gemini triage draft, analyst's first response decision, judged on MTTR and decision quality against a manual baseline. Alert input is manual for now; there is no Wazuh ingestion yet.

Run the tests with `python3 -m unittest discover -s tests`. `ioc_extract.py` stays free of Streamlit imports so the tests (and later the extraction-accuracy evaluation) can import it.

## Invariants

Each one protects the validity of the thesis results.

- **Blind** mode keeps the analyst status out of the prompt: `generate_prompt(..., None)`. The status is compared with `parse_ai_verdict` only after Gemini answers. Assisted-mode runs show the status to the AI, so they stay out of accuracy numbers.
- Every CTI lookup goes through `run_cti`, which records source, queried value, UTC retrieval time, status, and finding. A new source is one more `run_cti` call.
- TLS verification is on by default (`tls_verify()`). The sidebar checkbox is the only way to turn it off, and each history entry stores `tls_verify`.
- Raw alert text never reaches Gemini. Only the IoCs extracted from it do.

## Gotchas

- `app.py` uses CRLF line endings. Keep them; a whole-file diff hides the real change.
- `parse_ai_verdict` reads `Conclusion: <True Positive|False Positive|Likely Benign>`. Changing that line in the prompt template breaks verdict comparison.
- Behind an SSL-inspecting proxy, verification fails with `CERTIFICATE_VERIFY_FAILED`. Point `REQUESTS_CA_BUNDLE` (requests) and `SSL_CERT_FILE` (Gemini via httpx) at the corporate CA, or untick the sidebar checkbox.
- The prompt's "Initial Verdict" is a VirusTotal/AbuseIPDB threshold heuristic. It can anchor the AI, and blind mode does not remove it.
- History lives in `st.session_state` only. A page refresh erases evaluation data.
- The Converter tab is an empty placeholder (its code is commented out). The Bulk Parser tab was removed on purpose.
