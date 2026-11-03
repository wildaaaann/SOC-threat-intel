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
- Values from `st.secrets` never go into a widget's `value=`: Streamlit sends it to the visitor's browser even for `type="password"`. Key inputs stay empty and `secret_input()` falls back to the server value; the Wazuh URL, user and password follow the same rule, and the UI never prints the server's Indexer URL. Rerun the secrets-leak AppTest after touching the sidebar or the Wazuh connection form.
- Every LLM call goes through `run_chain` (`llm_providers.py`). Each trial stores `llm_provider`, `llm_model`, and whether a fallback ran. Compute accuracy per provider and model, never pooled: a fallback run is a different model.
- MTTR is `decision time - alert loaded into the platform`, measured with a monotonic clock. `system_latency_s` (CTI + AI wait) is stored separately so the thesis can report MTTR with or without it.
- **Mode Otomatis** (`worker.py`, `ticket_policy.py`) is separate from the thesis experiment: its tickets never enter `data/trials.jsonl` or the accuracy and MTTR numbers. It closes a ticket only through `ticket_policy.decide`; a failed VirusTotal lookup, a missing layer, an unreadable verdict or severity, or a verdict/severity contradiction holds the ticket as "Perlu manusia". True Positive and High/Critical closures stay mandatory-review. Never loosen `decide` to raise the auto-close rate.
- Tickets keep the AI's four fields (`severity`, `closing_reason`, `description`, `recommendations`) apart from the reviewer's (`final_*`). A review never overwrites the AI value, because agreement between the two is a result the thesis reports.
- Trials live in `data/trials.jsonl` (`TrialStore`, append-only, gitignored). Rubric scores are `_update` lines merged on read. Never commit `data/`.

## Gotchas

- `app.py` uses CRLF line endings. Keep them; a whole-file diff hides the real change.
- The report template (`SOC_ANALYST_ROLE` in `triage_prompt.py`) and `triage_report.py` change together: the `Conclusion:`, `Severity:`, `Closing Reason:` and `Description:` lines, the `LAYER 1/2/3` and `RECOMMENDATIONS` headings, and the parsers (`parse_ai_verdict`, `parse_layers`, `parse_severity`, ...). Run `tests/test_triage_report.py` and `tests/test_tickets.py` after either side changes.
- `RESPONSE_ACTIONS` (`scenarios.py`) and the three starter scenarios are drafts, and the scenarios are synthetic with `validated: false`. Replace them once the supervisor or mentor agrees on the definitions and answer keys.
- The Wazuh tab reads the Wazuh Indexer (`wazuh-alerts-*`, port 9200), not the manager REST API. It has only been tested against fake responses, never a live Wazuh.
- Behind an SSL-inspecting proxy, verification fails with `CERTIFICATE_VERIFY_FAILED`. Point `REQUESTS_CA_BUNDLE` (requests) and `SSL_CERT_FILE` (Gemini via httpx) at the corporate CA, or untick the sidebar checkbox. A lab Wazuh Indexer usually needs its own `root-ca.pem` in the tab's CA field.
- The prompt's "Initial Verdict" is a VirusTotal/AbuseIPDB threshold heuristic. It can anchor the AI, and blind mode does not remove it.
- Free-tier model names retire often: on 2026-11-03 `gemini-2.5-flash` (404), `meta/llama-3.3-70b-instruct` on NVIDIA (410), Groq and OpenRouter (404) all failed at once. Defaults in `llm_providers.py` were then re-picked from vendor docs but never tried with a live key. A retired name shows as a failed row in `llm_log`; the sidebar button "Cek model yang tersedia" lists what each provider offers now. OpenRouter's default `openrouter/free` is a router: `run_chain` records the model that actually answered as `router -> served`, so keep accuracy per served model.
- Smaller fallback models may ignore the `Conclusion:` line, which shows up as "Tidak terbaca" in verdict comparison.
- Gemini's unpaid tier may use submitted content to improve Google products (terms: ai.google.dev/gemini-api/terms). Treat every free tier as public.
- The History tab lives in `st.session_state` and is erased by a refresh. Trials in `data/` survive, except on hosts with a temporary disk (Streamlit Cloud): download the JSONL regularly.
- Set `EVALUATOR_PIN` in secrets before testing with analysts; without it a checkbox reveals the answer keys.
- The worker has only run against a fake Indexer, never a live Wazuh. Timestamps are queried as UTC `...Z`; confirm against a real index.
- One alert costs 3-4 VirusTotal requests. `worker.py` spaces them (`VT_MIN_INTERVAL_S`) and caches successful lookups for 24 h (`CtiCache`); the free quota is the limit on alert rate, and a backlog shows in the Wazuh tab.
- Alerts with no public IoC cannot be enriched and become "Perlu manusia". Expect many on internal-heavy logs.
- `extract_entities` merges one value found in several SIEM fields into a single row whose `field` lists all of them; the entity table is for the reader and never goes to an LLM.
- `ioc_utils.py` duplicates `ioc_extract.py` and `app.py` does not import it. Keep one.
