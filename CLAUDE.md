# SOC Threat Intel

Streamlit prototype for the skripsi "Wazuh + CTI + generative AI incident triage". Bab 1 flow: alert, CTI enrichment, LLM triage draft, analyst's first response decision, judged on MTTR and decision quality against a manual baseline.

Run the tests with `python3 -m unittest discover -s tests`. Every module besides `app.py` stays free of Streamlit imports so the tests and the later evaluation scripts can import them. `app.py` itself is covered only by AppTest flows run outside the repo; rerun a flow after touching it.

## Invariants

Each one protects the validity of the thesis results.

- **Blind** mode keeps the analyst status out of the prompt: `generate_prompt(..., None)`. The status is compared with `parse_ai_verdict` only after the model answers. Assisted-mode runs show the status to the AI, so they stay out of accuracy numbers.
- Scenario **ground truth** stays hidden until the analyst's decision is recorded: not in the Uji Skenario tab, not in History, not in Evaluasi without the evaluator gate.
- The decision form has no preselected answer. A default would record answers nobody chose.
- Every CTI lookup goes through `run_cti`, which records source, queried value, UTC retrieval time, status, and finding. A new source is one more `run_cti` call.
- TLS verification is on by default (`tls_verify()`). The sidebar checkbox is the only way to turn it off, and each trial and history entry stores `tls_verify`.
- Raw alert text and Wazuh identity fields (agent, location, `full_log`) never reach any LLM provider. Only the extracted IoCs, the alert name, the action text, the CTI results, and the `LLM_SAFE_FIELDS` listed in `wazuh_client.py` do.
- Every LLM call goes through `run_chain` (`llm_providers.py`). Each trial stores `llm_provider`, `llm_model`, and whether a fallback ran. Compute accuracy per provider and model, never pooled: a fallback run is a different model.
- MTTR is `decision time - alert loaded into the platform`, measured with a monotonic clock. `system_latency_s` (CTI + AI wait) is stored separately so the thesis can report MTTR with or without it.
- Trials live in `data/trials.jsonl` (`TrialStore`, append-only, gitignored). Rubric scores are `_update` lines merged on read. Never commit `data/`.

## Gotchas

- `app.py` uses CRLF line endings. Keep them; a whole-file diff hides the real change.
- The report template (`SOC_ANALYST_ROLE` in `app.py`) and `triage_report.py` change together: the `Conclusion:` line, the `LAYER 1/2/3` headings, and `parse_ai_verdict` / `parse_layers`. Run `tests/test_triage_report.py` after either side changes.
- `RESPONSE_ACTIONS` (`scenarios.py`) and the three starter scenarios are drafts, and the scenarios are synthetic with `validated: false`. Replace them once the supervisor or mentor agrees on the definitions and answer keys.
- The Wazuh tab reads the Wazuh Indexer (`wazuh-alerts-*`, port 9200), not the manager REST API. It has only been tested against fake responses, never a live Wazuh.
- Behind an SSL-inspecting proxy, verification fails with `CERTIFICATE_VERIFY_FAILED`. Point `REQUESTS_CA_BUNDLE` (requests) and `SSL_CERT_FILE` (Gemini via httpx) at the corporate CA, or untick the sidebar checkbox. A lab Wazuh Indexer usually needs its own `root-ca.pem` in the tab's CA field.
- The prompt's "Initial Verdict" is a VirusTotal/AbuseIPDB threshold heuristic. It can anchor the AI, and blind mode does not remove it.
- Default model names in `llm_providers.py` are editable starting points, not verified current. A retired name shows up as a failed row in `llm_log`.
- Smaller fallback models may ignore the `Conclusion:` line, which shows up as "Tidak terbaca" in verdict comparison.
- Gemini's unpaid tier may use submitted content to improve Google products (terms: ai.google.dev/gemini-api/terms). Treat every free tier as public.
- The History tab lives in `st.session_state` and is erased by a refresh. Trials in `data/` survive, except on hosts with a temporary disk (Streamlit Cloud): download the JSONL regularly.
- Set `EVALUATOR_PIN` in secrets before testing with analysts; without it a checkbox reveals the answer keys.
- `ioc_utils.py` duplicates `ioc_extract.py` and `app.py` does not import it. Keep one.
