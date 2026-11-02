import streamlit as st
import hmac
import os
import re
import json
import urllib3
from datetime import datetime, timezone
from ioc_extract import extract_iocs, pick_primary, first_public_ip
from llm_providers import OPENAI_COMPATIBLE, build_attempts, gemini_generate
from triage_pipeline import enrich, generate_report
from time import monotonic as _monotonic
from triage_report import (SEVERITIES, VERDICTS, UNREADABLE, parse_ai_verdict, layers_complete, layers_status,
                           parse_closing_reason, parse_description, parse_recommendations, parse_severity)
from ticket_policy import (PRIORITY_HUMAN, REVIEW_PENDING, STATUS_CLOSED_AI, STATUS_NEEDS_HUMAN, review_changes,
                           sort_for_review, summarize_tickets)
from ticket_store import TicketStore, read_worker_state, tickets_to_csv
from wazuh_client import WazuhError, alert_label, alert_to_inputs, fetch_alerts, parse_alerts_file, parse_timestamp
from scenarios import RESPONSE_ACTIONS, load_scenarios, parse_scenarios
from trial_store import CSV_FIELDS, TrialStore, new_trial_id, trials_to_csv, utc_now_iso
from evaluation import (CONDITION_LABEL, ai_is_correct, data_quality, format_rows, paired_comparison,
                        score_decision, scored, summarize_conditions, summarize_models)

# --- MENCEGAH WARNING SSL MUNZUL DI TERMINAL ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- FUNGSI HELPER ---
def tls_verify():
    """Verifikasi sertifikat SSL aktif secara default. Hanya mati jika analis mematikannya di sidebar."""
    return st.session_state.get("tls_verify", True)

# --- INISIALISASI SESSION STATE UNTUK HISTORY ---
if "history" not in st.session_state:
    st.session_state.history = []

# --- UI STREAMLIT ---
st.set_page_config(page_title="SOC Threat Intel @wildaan", page_icon="🛡️", layout="wide")

# --- TEMA (hanya tampilan, lihat theme.py dan .streamlit/config.toml) ---
from theme import apply_theme
apply_theme()

st.title("SOC Threat Inteligence Dashboard")
st.markdown("Automation gathering threat Inteligence and report @wildaaan.")

# --- AMBIL DATA DARI STREAMLIT SECRETS (Dengan Penanganan Error Lanjutan) ---
ENV_GEMINI = ""
ENV_VT = ""
ENV_ABUSE = ""
ENV_URLSCAN = ""
ENV_HYBRID = ""
ENV_LLM = {}
ENV_WAZUH = {}
ENV_EVAL_PIN = ""

try:
    ENV_GEMINI = st.secrets.get("GEMINI_API_KEY", "")
    ENV_VT = st.secrets.get("VT_API_KEY", "")
    ENV_ABUSE = st.secrets.get("ABUSEIPDB_API_KEY", "")
    ENV_URLSCAN = st.secrets.get("URLSCAN_API_KEY", "")
    ENV_HYBRID = st.secrets.get("HYBRID_API_KEY", "")
    ENV_LLM = {
        "NVIDIA NIM": st.secrets.get("NVIDIA_API_KEY", ""),
        "Groq": st.secrets.get("GROQ_API_KEY", ""),
        "OpenRouter": st.secrets.get("OPENROUTER_API_KEY", ""),
    }
    ENV_WAZUH = {
        "url": st.secrets.get("WAZUH_INDEXER_URL", ""),
        "user": st.secrets.get("WAZUH_USER", ""),
        "password": st.secrets.get("WAZUH_PASSWORD", ""),
    }
    ENV_EVAL_PIN = st.secrets.get("EVALUATOR_PIN", "")
except:
    pass # Jika secrets.toml tidak ada di lokal, biarkan kosong

# --- SIDEBAR KONFIGURASI API ---
st.sidebar.header("Konfigurasi API")
gemini_key = st.sidebar.text_input("Gemini API Key (Wajib, atau isi salah satu penyedia cadangan)", type="password", value=ENV_GEMINI)
with st.sidebar.expander("Penyedia AI cadangan (gratis)"):
    st.caption("Dipakai berurutan bila penyedia sebelumnya gagal (batas gratis habis, server sibuk). Kosongkan key untuk melewati penyedia.")
    llm_extra = {}
    for _name, _cfg in OPENAI_COMPATIBLE.items():
        llm_extra[_name] = {
            "key": st.text_input(f"{_name} API Key", type="password", value=ENV_LLM.get(_name, ""), key=f"llm_key_{_name}"),
            "model": st.text_input(f"Model {_name}", value=_cfg["model"], key=f"llm_model_{_name}"),
        }
    llm_fallback = st.checkbox(
        "Fallback otomatis ke penyedia lain",
        value=True,
        key="llm_fallback",
        help="Matikan saat pengujian skripsi agar semua laporan berasal dari satu model. Penyedia dan model dicatat di setiap riwayat.",
    )
st.sidebar.markdown("---")
vt_key = st.sidebar.text_input("VirusTotal API Key (Wajib)", type="password", value=ENV_VT)
abuse_key = st.sidebar.text_input("AbuseIPDB API Key (Wajib)", type="password", value=ENV_ABUSE)
st.sidebar.markdown("---")
urlscan_key = st.sidebar.text_input("URLScan API Key (Opsional)", type="password", value=ENV_URLSCAN)
hybrid_key = st.sidebar.text_input("HybridAnalysis API Key (Opsional)", type="password", value=ENV_HYBRID)
st.sidebar.markdown("---")
st.sidebar.checkbox(
    "Verifikasi sertifikat SSL (disarankan)",
    value=True,
    key="tls_verify",
    help="Matikan hanya jika jaringan Anda memakai SSL inspection dan CA perusahaan belum dipasang. Pilihan ini dicatat di setiap riwayat analisis.",
)
if not st.session_state.get("tls_verify", True):
    st.sidebar.warning("Verifikasi SSL mati: request ke VirusTotal, AbuseIPDB, URLScan, HybridAnalysis, TIP Neiki, dan Gemini tidak memeriksa sertifikat server.")

# ==========================================
# BAGIAN BERSAMA: PIPELINE ANALISIS, HASIL, DAN KEPUTUSAN RESPONS
# ==========================================
MODE_BLIND = "Blind: AI menilai sendiri (untuk pengujian)"
MODE_ASSISTED = "Dibantu: status analis dikirim ke AI"
COND_MANUAL = "Manual (tanpa platform)"
COND_PLATFORM = "Platform (CTI + laporan AI)"
STATUS_OPTIONS = ["Belum ditentukan", "True Positive", "False Positive", "Likely Benign"]

try:
    _APP_DIR = os.path.dirname(os.path.abspath(__file__))
except NameError:
    _APP_DIR = os.getcwd()
SCENARIO_FILE = os.path.join(_APP_DIR, "scenarios", "scenarios.json")
STORE = TrialStore(os.environ.get("TRIALS_PATH", os.path.join(_APP_DIR, "data", "trials.jsonl")))
TICKETS = TicketStore(os.environ.get("TICKETS_PATH", os.path.join(_APP_DIR, "data", "tickets.jsonl")))
WORKER_STATE_PATH = os.path.join(os.path.dirname(TICKETS.path), "worker_state.json")  # sama dengan worker.py

if "runs" not in st.session_state:
    st.session_state.runs = {}
if "run_counter" not in st.session_state:
    st.session_state.run_counter = 0


def gemini_call(prompt_text, key, model):
    return gemini_generate(prompt_text, key, model, verify=tls_verify())


def run_pipeline(*, alert_name, ioc_input, analyst_status, action, related_ip, raw_text, analysis_mode, alert_fields=None):
    """Pengayaan CTI lalu laporan AI. Mengembalikan dict hasil, atau {"error": pesan} bila masukan belum lengkap."""
    if analysis_mode == MODE_ASSISTED and analyst_status is None:
        return {"error": "Mode Dibantu butuh Status Alert. Pilih statusnya, atau ganti ke mode Blind."}
    if not vt_key or not abuse_key or not build_attempts(gemini_key, llm_extra):
        return {"error": "Harap masukkan VirusTotal, AbuseIPDB, dan minimal satu API Key AI (Gemini atau penyedia cadangan) di menu Sidebar terlebih dahulu."}

    verify = tls_verify()
    # Mode Blind: status analis tidak dikirim ke AI (None).
    prompt_status = analyst_status if analysis_mode == MODE_ASSISTED else None
    with st.spinner("1/2: Mengambil data intel dari sumber CTI..."):
        ctx = enrich(
            alert_name=alert_name, ioc_input=ioc_input, related_ip=related_ip, raw_text=raw_text, action=action,
            alert_fields=alert_fields, prompt_status=prompt_status,
            keys={"vt": vt_key, "abuse": abuse_key, "urlscan": urlscan_key, "hybrid": hybrid_key}, verify=verify,
        )
    if "error" in ctx:
        return ctx

    with st.spinner("2/2: Menghasilkan Laporan Akhir dengan AI..."):
        gen = generate_report(ctx, build_attempts(gemini_key, llm_extra, llm_fallback), gemini_call, verify)

    # --- BANDINGKAN VERDICT AI DENGAN STATUS ANALIS (setelah AI menjawab) ---
    is_blind = analysis_mode == MODE_BLIND
    ai_verdict = parse_ai_verdict(gen["report"]) if is_blind else "-"
    if not is_blind:
        match_label = "Tidak dinilai (mode Dibantu)"
    elif analyst_status is None:
        match_label = "Tidak ada pembanding"
    elif ai_verdict == UNREADABLE:
        match_label = "Verdict AI tidak terbaca"
    else:
        match_label = "Cocok" if ai_verdict == analyst_status else "Tidak cocok"

    return {
        "ioc": ctx["ioc"], "ioc_type": ctx["ioc_type"], "alert_name": alert_name, "analysis_mode": analysis_mode, "is_blind": is_blind,
        "analyst_status": analyst_status, "final_prompt": ctx["final_prompt"], "collated": ctx["collated"], "report": gen["report"],
        "llm_used": gen["llm_used"], "llm_log": gen["llm_log"], "llm_fallback_used": gen["llm_fallback_used"],
        "ai_verdict": ai_verdict, "match_label": match_label, "cti_log": ctx["cti_log"], "extracted_iocs": ctx["extracted_iocs"],
        "target_ip": ctx["target_ip"], "cert_failed": gen["cert_failed"], "layers": gen["layers"],
        "layers_ok": gen["layers_ok"], "tls_verify": verify,
    }


def add_history(res, status_label, hide_comparison=False):
    # Skenario berkunci: hasil pembandingan memuat kunci jawaban, jadi disembunyikan dari tab History.
    # Menggunakan .insert(0, ...) agar riwayat terbaru selalu muncul paling atas
    st.session_state.history.insert(0, {
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "ioc": res["ioc"],
        "alert_name": res["alert_name"],
        "status": status_label,
        "report": res["report"],
        "raw_prompt": res["final_prompt"],
        "mode": res["analysis_mode"],
        "ai_verdict": res["ai_verdict"],
        "match_label": "Disembunyikan (skenario berkunci)" if hide_comparison else res["match_label"],
        "tls_verify": res["tls_verify"],
        "cti_log": res["cti_log"],
        "llm_provider": res["llm_used"]["provider"],
        "llm_model": res["llm_used"]["model"],
        "llm_log": res["llm_log"],
    })


def start_timer():
    """Titik awal MTTR: alert dimuat ke platform. Waktu dihitung dari jam monotonik, UTC hanya untuk catatan."""
    return {"t_start_utc": utc_now_iso(), "m_start": _monotonic(), "m_ready": None, "t_ready_utc": None}


def start_run(key, res, timer, meta):
    """Simpan satu sesi analisis di session_state supaya tetap tampil saat form keputusan dikirim."""
    if res is not None:
        timer["m_ready"] = _monotonic()
        timer["t_ready_utc"] = utc_now_iso()
    st.session_state.run_counter += 1
    st.session_state.runs[key] = {"id": st.session_state.run_counter, "res": res, "timer": timer, "meta": meta, "decision": None}


def render_result(res, key, run_id, show_comparison=True):
    st.success("Analisis Selesai!")
    st.caption(f"Laporan dibuat oleh {res['llm_used']['provider']} ({res['llm_used']['model']}).")
    if len(res["llm_log"]) > 1 or res["llm_fallback_used"]:
        st.warning("Penyedia AI utama gagal, laporan memakai penyedia cadangan. Jangan campur hasil beberapa model saat menghitung akurasi: hitung per penyedia dan model.")
        st.table(res["llm_log"])

    # Sumber CTI dan waktu pengambilan selalu terlihat oleh analis
    st.subheader("Sumber CTI & Waktu Pengambilan")
    st.table(res["cti_log"])

    if res["cert_failed"]:
        st.warning("Verifikasi sertifikat SSL gagal. Jika jaringan Anda memakai SSL inspection, arahkan REQUESTS_CA_BUNDLE dan SSL_CERT_FILE ke CA perusahaan, atau matikan 'Verifikasi sertifikat SSL' di sidebar (pilihan ini dicatat di riwayat).")

    if res["extracted_iocs"]:
        st.subheader("IoC Hasil Ekstraksi")
        st.table([{
            "IoC": i["value"],
            "Tipe": i["type"],
            "Publik": "ya" if i["public"] else "tidak (tidak diperkaya)",
            "Peran": "Primary" if i["value"] == res["ioc"] else ("Related IP" if i["value"] == res["target_ip"] else "Konteks"),
        } for i in res["extracted_iocs"]])

    if res["is_blind"]:
        if show_comparison:
            verdict_summary = f"Verdict AI: {res['ai_verdict']} | Status analis: {res['analyst_status'] or 'Belum ditentukan'} | {res['match_label']}"
            if res["match_label"] == "Cocok":
                st.success(verdict_summary)
            elif res["match_label"] == "Tidak cocok":
                st.warning(verdict_summary)
            else:
                st.info(verdict_summary)
    else:
        st.info("Mode Dibantu: status analis ikut dikirim ke AI, jadi hasil ini tidak boleh dipakai untuk mengukur ketepatan penilaian AI.")

    if not res["layers_ok"]:
        missing = [name for name, ok in res["layers"].items() if not ok]
        st.warning(f"Laporan tidak memuat semua lapisan templat (fakta alert, pengayaan CTI, inferensi AI). Lapisan yang hilang: {', '.join(missing)}. Kejadian ini dicatat pada hasil evaluasi.")

    # Empat kolom hasil AI. Ini bukan formulir keputusan: keputusan analis tetap dicatat di form terpisah.
    st.subheader("Hasil AI per kolom")
    st.table([{"Kolom": label, "AI": value if value and value != UNREADABLE else "(tidak terbaca)"} for label, value in ai_columns(
        parse_severity(res["report"]), parse_closing_reason(res["report"]), parse_description(res["report"]), parse_recommendations(res["report"]))])

    # Menampilkan Laporan Akhir
    st.subheader("Final Report :")
    st.text_area("Copy atau edit teks di bawah ini:", value=res["report"], height=400, key=f"report_text_{key}_{run_id}")

    # --- Tombol Download Prompt Mentah (Fallback) ---
    filename = f"prompt_{res['ioc'].replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    st.download_button(
        label=f"Download Exported File: {filename}",
        data=res["final_prompt"],
        file_name=filename,
        mime="text/plain",
        key=f"download_prompt_{key}_{run_id}",
    )

    # Tampilkan Data Mentah
    with st.expander("See Raw JSON Data"):
        st.code(res["collated"], language='json')


def decision_form(key):
    """Form keputusan respons pertama. Mengirimnya menghentikan timer dan menyimpan satu trial."""
    run = st.session_state.runs.get(key)
    if not run:
        return
    meta, res = run["meta"], run["res"]
    st.markdown("---")
    if run["decision"]:
        d = run["decision"]
        st.success(f"Keputusan tercatat: {d['decision_action']} ({d['decision_verdict']}). MTTR {d['mttr_s']:.1f} detik.")
        return

    st.subheader("Keputusan respons pertama")
    st.caption("Timer MTTR berjalan sejak alert dimuat dan berhenti saat tombol di bawah ditekan. Isi alasan singkat sebelum menekan tombol.")
    suffix = f"{key}_{run['id']}"
    with st.form(f"decision_form_{suffix}"):
        if meta.get("participant"):
            st.write(f"**Kode analis:** {meta['participant']}")
            participant = meta["participant"]
        else:
            participant = st.text_input("Kode analis:", value=st.session_state.get("participant_code", ""), key=f"dec_participant_{suffix}")
        decision_action = st.selectbox("Aksi respons pertama:", RESPONSE_ACTIONS, index=None, placeholder="Pilih aksi", key=f"dec_action_{suffix}")
        decision_verdict = st.selectbox("Verdict akhir analis:", list(VERDICTS), index=None, placeholder="Pilih verdict", key=f"dec_verdict_{suffix}")
        decision_note = st.text_area("Alasan singkat (bukti yang mendasari keputusan):", key=f"dec_note_{suffix}")
        submitted = st.form_submit_button("Catat keputusan dan hentikan timer")

    if not submitted:
        return
    # Tanpa pilihan bawaan: jawaban yang tidak dipilih sadar akan mencemari data evaluasi. Timer tetap berjalan.
    if decision_action is None or decision_verdict is None:
        st.error("Pilih aksi respons pertama dan verdict akhir terlebih dahulu. Timer tetap berjalan.")
        return
    now_m = _monotonic()
    timer = run["timer"]
    mttr = now_m - timer["m_start"]
    ready = timer.get("m_ready")
    alert_ts = meta.get("alert_timestamp")
    truth = meta.get("truth")
    verdict_ok, action_ok = score_decision(decision_verdict, decision_action, truth)
    platform = meta["condition"] == "platform" and res is not None
    st.session_state.participant_code = participant
    trial = {
        "participant": participant.strip() or "-",
        "condition": meta["condition"],
        "source": meta["source"],
        "scenario_id": meta.get("scenario_id"),
        "alert_name": (res or {}).get("alert_name") or meta.get("alert_name", ""),
        "ioc": (res or {}).get("ioc", ""),
        "t_start_utc": timer["t_start_utc"],
        "t_report_ready_utc": timer.get("t_ready_utc"),
        "t_decision_utc": utc_now_iso(),
        "mttr_s": round(mttr, 2),
        "system_latency_s": round(ready - timer["m_start"], 2) if (platform and ready) else None,
        "analyst_time_s": round(now_m - ready, 2) if (platform and ready) else round(mttr, 2),
        "mttr_from_alert_s": round((datetime.now(timezone.utc) - alert_ts).total_seconds(), 1) if alert_ts else None,
        "decision_verdict": decision_verdict,
        "decision_action": decision_action,
        "decision_note": decision_note.strip(),
        "ground_truth_verdict": truth["verdict"] if truth else None,
        "correct_actions": list(truth["correct_actions"]) if truth else None,
        "verdict_correct": verdict_ok,
        "action_correct": action_ok,
        "ai_verdict": res["ai_verdict"] if platform else None,
        "ai_correct": ai_is_correct(res["ai_verdict"], truth) if platform else None,
        "report_layers_ok": res["layers_ok"] if platform else None,
        "llm_provider": res["llm_used"]["provider"] if platform else None,
        "llm_model": res["llm_used"]["model"] if platform else None,
        "llm_fallback_used": res["llm_fallback_used"] if platform else None,
        "analysis_mode": res["analysis_mode"] if platform else None,
        "tls_verify": res["tls_verify"] if platform else None,
        "report": res["report"] if platform else None,
    }
    try:
        trial = STORE.append(trial)
    except OSError as exc:
        trial["id"] = new_trial_id()
        st.session_state.setdefault("unsaved_trials", []).append(trial)
        st.error(f"Trial tidak bisa ditulis ke {STORE.path} ({exc}). Data ditahan di sesi ini; unduh dari tab Evaluasi sebelum menutup halaman.")
    run["decision"] = {"decision_action": decision_action, "decision_verdict": decision_verdict, "mttr_s": mttr, "trial_id": trial["id"]}
    st.rerun()


def show_run(key):
    run = st.session_state.runs.get(key)
    if not run:
        return
    if run["res"] is not None:
        # Pada skenario berkunci, hasil pembandingan dengan kunci jawaban baru tampil setelah keputusan tercatat.
        hide = run["meta"].get("truth") is not None and run["decision"] is None
        render_result(run["res"], key, run["id"], show_comparison=not hide)
    decision_form(key)


def get_scenarios():
    """(skenario, pesan_kesalahan): berkas unggahan bila ada, jika tidak berkas bawaan."""
    uploaded = st.session_state.get("uploaded_scenarios")
    if uploaded is not None:
        return uploaded["scenarios"], uploaded["errors"]
    return load_scenarios(SCENARIO_FILE)


def clip(text, limit=90):
    """Potong teks panjang untuk sel tabel; teks lengkap tetap ada di detail tiket dan CSV."""
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def ai_columns(severity, closing_reason, description, recommendations):
    """Empat kolom hasil AI dengan label yang sama di tab Alert Manual dan tiket otomatis."""
    return [("Severity", severity), ("Reason untuk closing", closing_reason), ("Description", description), ("RECOMMENDATIONS", recommendations)]


def render_ticket_queue():
    """Mode Otomatis: tiket yang dibuat worker. Manusia hanya membaca dan memastikan severity serta alasan penutupan."""
    st.subheader("Tiket otomatis dari Wazuh")
    st.markdown(
        "Alert Wazuh masuk sendiri lewat worker, diperkaya CTI dan AI, lalu ditutup AI beserta rekomendasi, deskripsi, severity, dan alasan penutupan. "
        "Tugas Anda: pastikan severity dan alasan penutupan sudah benar. Pengayaan tidak bisa dijalankan ulang dari sini."
    )

    state = read_worker_state(WORKER_STATE_PATH)
    last_cycle = state.get("last_cycle_utc")
    if not last_cycle:
        st.warning("Worker belum pernah berjalan. Jalankan `python3 worker.py` di server Wazuh (contoh layanan ada di folder deploy/).")
    else:
        try:
            age = (datetime.now(timezone.utc) - datetime.strptime(last_cycle, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)).total_seconds()
        except ValueError:
            age = 0
        poll = int(state.get("poll_seconds") or 60)
        if age > 3 * poll:
            st.error(f"Worker tidak aktif. Putaran terakhir {last_cycle} UTC ({int(age // 60)} menit lalu). Alert yang masuk sejak itu belum menjadi tiket.")
        else:
            st.caption(f"Worker aktif. Putaran terakhir {last_cycle} UTC. Level alert minimum {state.get('min_level', '?')}. Total diproses {state.get('processed_total', 0)}.")
        if state.get("last_error"):
            st.warning(f"Galat terakhir worker: {state['last_error']}")
        if state.get("backlog"):
            st.warning("Antrean menumpuk: worker belum mengejar alert terbaru. Penyebab umum: kuota CTI atau AI gratis, atau laju alert terlalu tinggi.")

    try:
        tickets = TICKETS.all()
    except OSError as exc:
        tickets = []
        st.error(f"Tidak bisa membaca {TICKETS.path}: {exc}")

    st.markdown("#### Ringkasan")
    st.table([{"Ukuran": k, "Nilai": str(v)} for k, v in format_rows([summarize_tickets(tickets)])[0].items()])
    st.caption("Severity dan alasan disetujui = seberapa sering reviewer setuju dengan AI. Dihitung dari tiket Closed by AI yang sudah direview.")

    if not tickets:
        st.info("Belum ada tiket. Tiket muncul setelah worker memproses alert Wazuh level yang memenuhi syarat.")
        return

    view = st.radio("Tampilkan:", ["Belum direview", "Semua", "Sudah direview"], horizontal=True, key="tk_filter")
    if view == "Belum direview":
        shown = [t for t in tickets if t.get("review_status") == REVIEW_PENDING]
    elif view == "Sudah direview":
        shown = [t for t in tickets if t.get("review_status") != REVIEW_PENDING]
    else:
        shown = list(tickets)
    shown = sort_for_review(shown)

    st.download_button("Unduh CSV tiket", tickets_to_csv(tickets), "tickets.csv", "text/csv", key="dl_tickets_csv")
    if not shown:
        st.info("Tidak ada tiket pada tampilan ini.")
        return

    st.caption("Kolom AI diisi otomatis oleh worker. Kolom Manual berisi nilai akhir dari reviewer dan kosong sampai tiket direview.")
    st.dataframe([{
        "Prioritas review": str(t.get("review_priority") or ""), "Status": str(t.get("status") or ""), "Verdict AI": str(t.get("ai_verdict") or ""),
        "Waktu alert": (t.get("alert_timestamp") or "")[:19], "Rule": clip(f"{t.get('rule_id', '')} {t.get('rule_description', '')}", 60),
        "Agent": str(t.get("agent_name") or ""), "IoC": t.get("ioc") or "-",
        "AI: Severity": str(t.get("severity") or ""), "AI: Reason untuk closing": clip(t.get("closing_reason")),
        "AI: Description": clip(t.get("description")), "AI: RECOMMENDATIONS": clip(t.get("recommendations")),
        "Manual: Severity": str(t.get("final_severity") or ""), "Manual: Reason untuk closing": clip(t.get("final_reason")),
        "Manual: Description": clip(t.get("final_description")), "Manual: RECOMMENDATIONS": clip(t.get("final_recommendations")),
        "Review": str(t.get("review_status") or ""),
    } for t in shown], hide_index=True)

    labels = {t["id"]: f"[{t.get('review_priority')}] {(t.get('alert_timestamp') or '')[:19]} | {t.get('rule_description') or '(tanpa deskripsi)'} | {t.get('ai_verdict')} / {t.get('severity')}" for t in shown}
    ticket_id = st.selectbox("Buka tiket:", list(labels), format_func=labels.get, key="tk_pick")
    render_ticket_detail(next(t for t in shown if t["id"] == ticket_id))


def render_ticket_detail(ticket):
    tid = ticket["id"]
    st.markdown("---")
    st.subheader(f"Tiket {ticket.get('rule_description') or tid}")
    if ticket["status"] == STATUS_NEEDS_HUMAN:
        st.error("AI tidak menutup tiket ini. Alasan: " + "; ".join(ticket.get("hold_reasons") or ["tidak diketahui"]) + ". Tiket menunggu keputusan manusia.")
    else:
        st.success(f"Ditutup oleh AI. Review: {ticket.get('review_priority')}.")
        if ticket.get("ai_verdict") == "True Positive":
            st.warning("AI menilai ini True Positive dan tetap menutupnya. Baca alasan penutupan dengan teliti sebelum mengonfirmasi.")

    c1, c2, c3 = st.columns(3)
    c1.metric("Verdict AI", ticket.get("ai_verdict") or "-")
    c2.metric("Severity AI", ticket.get("severity") or "-")
    c3.metric("Level rule Wazuh", ticket.get("rule_level") if ticket.get("rule_level") is not None else "-")

    reviewed = ticket.get("review_status") != REVIEW_PENDING
    col_ai, col_manual = st.columns(2)
    manual_values = {"Severity": ticket.get("final_severity"), "Reason untuk closing": ticket.get("final_reason"),
                     "Description": ticket.get("final_description"), "RECOMMENDATIONS": ticket.get("final_recommendations")}
    with col_ai:
        st.markdown("#### AI enrichment")
        for label, value in ai_columns(ticket.get("severity"), ticket.get("closing_reason"), ticket.get("description"), ticket.get("recommendations")):
            st.markdown(f"**{label}**")
            st.text(value or "(kosong)")
    with col_manual:
        st.markdown("#### Manual (reviewer)")
        for label in manual_values:
            st.markdown(f"**{label}**")
            st.text(manual_values[label] or ("(kosong)" if reviewed else "(belum direview)"))

    st.markdown("**Entities (nama field mengikuti SIEM):**")
    st.table([{"Field SIEM": e.get("field", "-"), "Tipe": e["type"], "Nilai": e["value"], "Peran": e["role"], "Publik": {True: "ya", False: "tidak"}.get(e.get("public"), "-")} for e in ticket.get("entities", [])])
    if ticket.get("cti_log"):
        st.markdown("**Sumber CTI dan waktu pengambilan:**")
        st.table(ticket["cti_log"])
    st.caption(f"Laporan dibuat oleh {ticket.get('llm_provider') or '-'} ({ticket.get('llm_model') or '-'}). "
               f"Verifikasi SSL: {'aktif' if ticket.get('tls_verify', True) else 'mati'}. Diproses {ticket.get('processed_at_utc')} UTC dalam {ticket.get('processing_s')} detik.")
    if ticket.get("llm_fallback_used"):
        st.warning("Penyedia AI utama gagal, laporan memakai penyedia cadangan.")
    if ticket.get("report"):
        with st.expander("Laporan lengkap AI"):
            st.text(ticket["report"])

    st.markdown("---")
    if ticket.get("review_status") != REVIEW_PENDING:
        st.success(
            f"Sudah direview oleh {ticket.get('reviewer')} ({ticket.get('review_status')}). Severity akhir: {ticket.get('final_severity')}. "
            f"Alasan akhir: {ticket.get('final_reason')}"
        )
        return

    st.subheader("Review")
    with st.form(f"review_form_{tid}"):
        reviewer = st.text_input("Kode reviewer:", value=st.session_state.get("participant_code", ""), key=f"rv_who_{tid}")
        final_severity = st.selectbox("Severity yang benar:", list(SEVERITIES), index=None, placeholder="Pilih severity", key=f"rv_sev_{tid}")
        if ticket["status"] == STATUS_CLOSED_AI:
            st.write(f"AI memberi severity **{ticket.get('severity')}**.")
            reason_choice = st.radio("Alasan penutupan AI sudah benar?", ["Benar", "Perlu koreksi"], index=None, key=f"rv_reason_{tid}")
            final_verdict = None
            reason_label = "Alasan penutupan yang benar (wajib bila 'Perlu koreksi'):"
        else:
            reason_choice = None
            final_verdict = st.selectbox("Verdict akhir:", list(VERDICTS), index=None, placeholder="Pilih verdict", key=f"rv_verdict_{tid}")
            reason_label = "Alasan penutupan:"
        corrected = st.text_area(reason_label, key=f"rv_text_{tid}")
        manual_description = st.text_area("Description manual (kosong = pakai teks AI):", key=f"rv_desc_{tid}")
        manual_recommendations = st.text_area("RECOMMENDATIONS manual (kosong = pakai teks AI):", key=f"rv_recs_{tid}")
        note = st.text_area("Catatan (opsional):", key=f"rv_note_{tid}")
        saved = st.form_submit_button("Simpan review")

    if saved:
        try:
            changes = review_changes(
                ticket, reviewer=reviewer, final_severity=final_severity,
                reason_ok=None if reason_choice is None else reason_choice == "Benar",
                corrected_reason=corrected, final_verdict=final_verdict, note=note,
                manual_description=manual_description, manual_recommendations=manual_recommendations,
            )
        except ValueError as exc:
            st.error(str(exc))
            return
        try:
            TICKETS.update(tid, changes)
        except OSError as exc:
            st.error(f"Review tidak bisa ditulis ke {TICKETS.path}: {exc}")
            return
        st.session_state.participant_code = reviewer.strip()
        st.rerun()


# --- MEMBAGI UI MENJADI TAB ---
tab_manual, tab_wazuh, tab_scenario, tab_eval, tab_history, tab_defang, tab_shift = st.tabs(
    ["Alert Manual", "Alert Wazuh", "Uji Skenario", "Evaluasi", "History", "Defang", "Shift Summarizer"]
)

# ==========================================
# TAB: ALERT MANUAL
# ==========================================
with tab_manual:
    with st.form("ioc_form"):
        col1, col2 = st.columns(2)
        with col1:
            alert_name = st.text_input("Alert Name:", placeholder="e.g., FGT utm:webfilter blocked")
            ioc = st.text_input("Primary IoC (kosong = ambil dari Raw Alert):", placeholder="IP, Domain, MD5, SHA1, atau SHA256")
            final_verdict_decision = st.selectbox("Status Alert (keputusan analis / ground truth):", STATUS_OPTIONS)
        with col2:
            action = st.text_input("Action Taken (Opsional):", placeholder="e.g., Blocked")
            abuse_ip = st.text_input("Related IP untuk AbuseIPDB (Opsional):", placeholder="Masukkan IP jika IoC utama adalah Domain/Hash")
        raw_alert = st.text_area(
            "Raw Alert / Log (Opsional, IoC diekstrak otomatis):",
            height=120,
            placeholder="Tempel isi alert. IP, domain, URL, dan hash dikenali otomatis, termasuk yang di-defang (evil[.]com, hxxp).",
        )
        analysis_mode = st.radio(
            "Mode analisis:",
            [MODE_BLIND, MODE_ASSISTED],
            horizontal=True,
            help="Blind: status analis tidak dikirim ke AI dan hanya dipakai sebagai pembanding setelah AI menjawab. Dibantu: status ikut dikirim ke AI, sehingga hasilnya tidak valid untuk mengukur ketepatan penilaian AI.",
        )

        submit_button = st.form_submit_button("Mulai Analisis & Generate Laporan")

    if submit_button:
        timer = start_timer()
        analyst_status = None if final_verdict_decision == "Belum ditentukan" else final_verdict_decision
        res = run_pipeline(
            alert_name=alert_name, ioc_input=ioc, analyst_status=analyst_status, action=action, related_ip=abuse_ip,
            raw_text=raw_alert, analysis_mode=analysis_mode,
        )
        if "error" in res:
            st.error(res["error"])
        else:
            start_run("manual", res, timer, {"source": "manual", "condition": "platform", "alert_name": alert_name})
            add_history(res, final_verdict_decision)

    show_run("manual")

# ==========================================
# TAB: ALERT WAZUH
# ==========================================
with tab_wazuh:
    wz_view = st.radio("Mode:", ["Tiket otomatis", "Ambil manual"], horizontal=True, key="wz_view")
    if wz_view == "Tiket otomatis":
        render_ticket_queue()
    else:
        st.subheader("Alert dari Wazuh")
        st.markdown("Ambil alert langsung dari Wazuh Indexer, atau unggah berkas ekspor alert. Analisis berjalan dengan mode Blind: AI menilai sendiri dan tidak menerima status dari analis.")

        with st.expander("Koneksi Wazuh Indexer", expanded=not st.session_state.get("wazuh_alerts")):
            st.caption("Alert Wazuh disimpan di Wazuh Indexer (port 9200), bukan di API manager (port 55000). Lab biasanya memakai sertifikat self-signed: isi path root-ca.pem agar verifikasi SSL global tidak perlu dimatikan.")
            wz_url = st.text_input("URL Wazuh Indexer:", value=ENV_WAZUH.get("url") or "https://localhost:9200", key="wz_url")
            wz_col1, wz_col2 = st.columns(2)
            with wz_col1:
                wz_user = st.text_input("Username Indexer:", value=ENV_WAZUH.get("user") or "", key="wz_user")
            with wz_col2:
                wz_pass = st.text_input("Password Indexer:", type="password", value=ENV_WAZUH.get("password") or "", key="wz_pass")
            wz_ca = st.text_input("Path CA Wazuh (opsional):", placeholder="/path/ke/root-ca.pem", key="wz_ca")
            wz_c1, wz_c2, wz_c3 = st.columns(3)
            with wz_c1:
                wz_level = st.number_input("Level rule minimum:", min_value=0, max_value=15, value=7, key="wz_level")
            with wz_c2:
                wz_hours = st.number_input("Jam terakhir:", min_value=1, max_value=720, value=24, key="wz_hours")
            with wz_c3:
                wz_size = st.number_input("Jumlah alert maksimum:", min_value=1, max_value=500, value=50, key="wz_size")
            wz_query = st.text_input("Filter tambahan (query string, opsional):", placeholder="agent.name:web01 AND rule.groups:authentication_failed", key="wz_query")
            wz_fetch = st.button("Ambil alert dari Wazuh", key="wz_fetch")

        wz_upload = st.file_uploader("Atau unggah berkas alert (alerts.json, ekspor Discover, array JSON)", type=["json", "ndjson", "log", "txt"], key="wz_upload")
        wz_load = st.button("Muat alert dari berkas", key="wz_load")

        if wz_fetch:
            try:
                with st.spinner("Mengambil alert dari Wazuh Indexer..."):
                    st.session_state.wazuh_alerts = fetch_alerts(
                        wz_url, wz_user, wz_pass, verify=(wz_ca.strip() or tls_verify()),
                        size=wz_size, min_level=wz_level, hours=wz_hours, query=wz_query,
                    )
                st.session_state.wazuh_source = f"Wazuh Indexer {wz_url}"
            except WazuhError as exc:
                st.error(str(exc))
        if wz_load:
            if wz_upload is None:
                st.error("Pilih berkas alert terlebih dahulu.")
            else:
                try:
                    st.session_state.wazuh_alerts = parse_alerts_file(wz_upload.getvalue().decode("utf8", errors="replace"))
                    st.session_state.wazuh_source = f"Berkas {wz_upload.name}"
                except WazuhError as exc:
                    st.error(str(exc))

        wz_alerts = st.session_state.get("wazuh_alerts") or []
        if st.session_state.get("wazuh_alerts") is not None and not wz_alerts:
            st.info("Tidak ada alert yang cocok dengan filter. Turunkan level minimum atau perlebar rentang jam.")
        if wz_alerts:
            st.caption(f"{len(wz_alerts)} alert dari {st.session_state.get('wazuh_source', '-')}")
            st.table([{
                "Waktu": a["timestamp"][:19], "Level": a["rule_level"], "Rule": f"{a['rule_id']} {a['rule_description']}",
                "Agent": a["agent_name"],
            } for a in wz_alerts])
            wz_index = st.selectbox("Pilih alert:", range(len(wz_alerts)), format_func=lambda i: alert_label(wz_alerts[i]), key="wz_pick")
            chosen = wz_alerts[wz_index]
            with st.expander("Isi alert (hanya tampil di layar ini)"):
                st.json(chosen["raw"])
            wz_ioc = st.text_input("IoC pilihan (kosong = otomatis dari alert):", placeholder="IP, domain, atau hash", key="wz_ioc")
            if st.button("Analisis alert terpilih", key="wz_analyze"):
                timer = start_timer()
                wz_inputs = alert_to_inputs(chosen)
                res = run_pipeline(
                    alert_name=wz_inputs["alert_name"], ioc_input=wz_ioc, analyst_status=None, action=wz_inputs["action"],
                    related_ip="", raw_text=wz_inputs["raw_text"], analysis_mode=MODE_BLIND, alert_fields=wz_inputs["llm_facts"],
                )
                if "error" in res:
                    st.error(res["error"])
                else:
                    start_run("wazuh", res, timer, {
                        "source": "wazuh", "condition": "platform", "alert_name": wz_inputs["alert_name"],
                        "alert_timestamp": parse_timestamp(chosen["timestamp"]),
                    })
                    add_history(res, "Belum ditentukan")

        show_run("wazuh")

# ==========================================
# TAB: UJI SKENARIO (PEMBANDING MANUAL VS PLATFORM)
# ==========================================
with tab_scenario:
    st.subheader("Uji Skenario")
    st.markdown("Setiap analis mengerjakan skenario yang sama pada dua kondisi: Manual (tanpa platform) dan Platform (CTI + laporan AI). Kunci jawaban tidak ditampilkan di tab ini.")

    scenarios, scenario_errors = get_scenarios()
    for message in scenario_errors:
        st.warning(message)
    with st.expander("Ganti set skenario (JSON)"):
        st.caption("Format: lihat scenarios/scenarios.json. Skenario bawaan hanya contoh dan belum divalidasi; ganti dengan set yang disepakati dengan dosen atau mentor.")
        scn_file = st.file_uploader("Berkas skenario", type=["json"], key="scn_upload")
        if st.button("Pakai berkas ini", key="scn_apply"):
            if scn_file is None:
                st.error("Pilih berkas skenario terlebih dahulu.")
            else:
                parsed, errors = parse_scenarios(scn_file.getvalue().decode("utf8", errors="replace"))
                st.session_state.uploaded_scenarios = {"scenarios": parsed, "errors": errors}
                st.rerun()
        if st.session_state.get("uploaded_scenarios") is not None and st.button("Kembali ke skenario bawaan", key="scn_reset"):
            st.session_state.uploaded_scenarios = None
            st.rerun()

    if not scenarios:
        st.info("Belum ada skenario yang valid.")
    else:
        if any(not s["validated"] for s in scenarios):
            st.info("Sebagian skenario belum ditandai validated. Jangan pakai hasilnya untuk Bab 4 sebelum kunci jawabannya disepakati.")
        scn_participant = st.text_input("Kode analis (mis. A01):", key="scn_participant")
        # Hanya id yang ditampilkan: judul skenario bisa membocorkan jawabannya.
        scn_id = st.selectbox("Skenario:", [s["id"] for s in scenarios], key="scn_pick")
        scn_condition = st.radio("Kondisi:", [COND_MANUAL, COND_PLATFORM], horizontal=True, key="scn_condition")

        done = {(t.get("participant"), t.get("scenario_id"), t.get("condition")) for t in STORE.all()}
        if scn_participant.strip():
            st.table([{
                "Skenario": s["id"],
                "Manual": "selesai" if (scn_participant.strip(), s["id"], "manual") in done else "belum",
                "Platform": "selesai" if (scn_participant.strip(), s["id"], "platform") in done else "belum",
            } for s in scenarios])

        if st.button("Mulai skenario (timer berjalan)", key="scn_start"):
            scn = next(s for s in scenarios if s["id"] == scn_id)
            if not scn_participant.strip():
                st.error("Kode analis wajib diisi.")
            elif (scn_participant.strip(), scn["id"], "manual" if scn_condition == COND_MANUAL else "platform") in done:
                st.error("Analis ini sudah menyelesaikan skenario dan kondisi tersebut.")
            else:
                timer = start_timer()
                meta = {
                    "source": "skenario", "condition": "manual" if scn_condition == COND_MANUAL else "platform",
                    "scenario_id": scn["id"], "participant": scn_participant.strip(), "alert_name": scn["alert_name"],
                    "truth": scn["ground_truth"], "alert_view": {k: scn[k] for k in ("alert_name", "alert_text", "action_taken")},
                }
                if scn_condition == COND_MANUAL:
                    start_run("scenario", None, timer, meta)
                else:
                    # Kunci jawaban dipakai hanya sebagai pembanding setelah AI menjawab (mode Blind).
                    res = run_pipeline(
                        alert_name=scn["alert_name"], ioc_input=scn["primary_ioc"], analyst_status=scn["ground_truth"]["verdict"],
                        action=scn["action_taken"], related_ip=scn["related_ip"], raw_text=scn["alert_text"], analysis_mode=MODE_BLIND,
                    )
                    if "error" in res:
                        st.error(res["error"])
                    else:
                        start_run("scenario", res, timer, meta)
                        add_history(res, "Belum ditentukan", hide_comparison=True)

        scn_run = st.session_state.runs.get("scenario")
        if scn_run:
            view = scn_run["meta"]["alert_view"]
            st.markdown("---")
            st.subheader(f"Alert skenario {scn_run['meta']['scenario_id']} ({'Manual' if scn_run['meta']['condition'] == 'manual' else 'Platform'})")
            st.write(f"**Alert Name:** {view['alert_name']}")
            st.write(f"**Action Taken:** {view['action_taken'] or 'N/A'}")
            st.code(view["alert_text"], language=None)
            if scn_run["meta"]["condition"] == "manual":
                st.caption("Kondisi Manual: gunakan prosedur biasa tanpa laporan platform, lalu catat keputusan Anda di bawah.")
        show_run("scenario")

# ==========================================
# TAB: EVALUASI
# ==========================================
with tab_eval:
    st.subheader("Evaluasi")
    try:
        eval_trials = STORE.all()
    except OSError as exc:
        eval_trials = []
        st.error(f"Tidak bisa membaca {STORE.path}: {exc}")
    unsaved = st.session_state.get("unsaved_trials", [])
    if unsaved:
        st.warning(f"{len(unsaved)} trial belum tersimpan di disk (penulisan gagal). Unduh JSONL di bawah sebelum menutup halaman.")
    all_trials = eval_trials + unsaved
    st.caption(f"Data trial tersimpan di {STORE.path}. Pada hosting dengan disk sementara berkas ini hilang saat aplikasi restart; unduh JSONL secara berkala.")
    if STORE.skipped_lines:
        st.warning(f"{STORE.skipped_lines} baris rusak di berkas data dilewati.")

    st.markdown("#### Kualitas data")
    st.table([{"Hal": k, "Jumlah": v} for k, v in data_quality(all_trials).items()])
    st.caption("Angka di bawah hanya statistik deskriptif. Jumlah trial kecil belum menyatakan signifikansi apa pun; jenis uji statistik menunggu keputusan dosen.")

    st.markdown("#### Rekap per kelompok")
    st.table(format_rows(summarize_conditions(all_trials)))
    st.markdown("#### Perbandingan berpasangan (analis x skenario yang sama)")
    st.table(format_rows([paired_comparison(all_trials)]))
    st.caption("Selisih = MTTR Platform dikurangi MTTR Manual. Nilai negatif berarti Platform lebih cepat.")
    st.markdown("#### Rekap per model AI (kelompok Platform)")
    model_rows = summarize_models(all_trials)
    if model_rows:
        st.table(format_rows(model_rows))
    else:
        st.info("Belum ada trial Platform pada skenario berkunci.")

    # Bagian di bawah memuat kunci jawaban per skenario. Analis yang belum mengerjakan skenario tidak boleh melihatnya.
    if ENV_EVAL_PIN:
        eval_pin = st.text_input("PIN penilai (untuk melihat kunci jawaban):", type="password", key="eval_pin")
        evaluator = bool(eval_pin) and hmac.compare_digest(eval_pin, ENV_EVAL_PIN)
    else:
        st.caption("EVALUATOR_PIN belum diatur di secrets. Atur PIN sebelum pengujian dengan analis agar kunci jawaban tidak terlihat oleh mereka.")
        evaluator = st.checkbox("Saya penilai: tampilkan kunci jawaban dan data per trial", key="eval_reveal")
    if not evaluator:
        st.info("Penilaian rubrik dan data per trial memuat kunci jawaban, jadi disembunyikan. Rekap di atas tidak membuka jawaban per skenario.")
    else:
        st.markdown("#### Penilaian rubrik")
        with st.expander("Rubrik penilaian (draf, menunggu persetujuan dosen)"):
            st.markdown(
                "**Kesesuaian kesimpulan dengan bukti**\n\n"
                "- 1: kesimpulan bertentangan dengan bukti yang tersedia, atau tanpa bukti.\n"
                "- 3: sebagian didukung bukti; ada bukti penting yang diabaikan.\n"
                "- 5: sepenuhnya didukung bukti dan bukti kunci disebut.\n\n"
                "**Relevansi rekomendasi respons**\n\n"
                "- 1: tidak relevan atau berisiko merugikan.\n"
                "- 3: relevan tetapi umum atau tidak lengkap.\n"
                "- 5: spesifik sesuai bukti dan langsung bisa dijalankan.\n\n"
                "Yang dinilai adalah keputusan dan alasan analis pada kedua kondisi, agar Manual dan Platform sebanding. Laporan AI ditampilkan hanya sebagai konteks."
            )
        scenario_by_id = {s["id"]: s for s in get_scenarios()[0]}
        rateable = sorted(scored(eval_trials), key=lambda t: (t.get("rubric_evidence") is not None, t.get("recorded_at_utc", "")))
        if not rateable:
            st.info("Belum ada trial skenario berkunci untuk dinilai.")
        else:
            rubric_labels = {
                t["id"]: f"{t['id']} | {t.get('participant', '-')} | {t.get('scenario_id')} | {CONDITION_LABEL.get(t.get('condition'), '-')}"
                         + (" | sudah dinilai" if t.get("rubric_evidence") is not None else "")
                for t in rateable
            }
            rubric_id = st.selectbox("Pilih trial:", list(rubric_labels), format_func=rubric_labels.get, key="rubric_pick")
            rubric_trial = next(t for t in rateable if t["id"] == rubric_id)
            scn = scenario_by_id.get(rubric_trial.get("scenario_id"))
            st.write(f"**Kunci jawaban:** {rubric_trial['ground_truth_verdict']} | aksi benar: {'; '.join(rubric_trial.get('correct_actions') or [])}")
            if scn and scn["ground_truth"].get("key_evidence"):
                st.write(f"**Bukti kunci:** {scn['ground_truth']['key_evidence']}")
            st.write(f"**Keputusan analis:** {rubric_trial.get('decision_verdict')} | {rubric_trial.get('decision_action')} | MTTR {rubric_trial.get('mttr_s')} detik")
            st.write(f"**Alasan analis:** {rubric_trial.get('decision_note') or '(kosong)'}")
            if rubric_trial.get("report"):
                with st.expander("Laporan AI (konteks)"):
                    st.text(rubric_trial["report"])
            with st.form(f"rubric_form_{rubric_id}"):
                rater = st.text_input("Kode penilai:", key=f"rubric_rater_{rubric_id}")
                score_evidence = st.select_slider("Kesesuaian kesimpulan dengan bukti (1-5):", options=[1, 2, 3, 4, 5], value=3, key=f"rubric_ev_{rubric_id}")
                score_reco = st.select_slider("Relevansi rekomendasi respons (1-5):", options=[1, 2, 3, 4, 5], value=3, key=f"rubric_rec_{rubric_id}")
                rubric_note = st.text_area("Catatan penilai (opsional):", key=f"rubric_note_{rubric_id}")
                rubric_save = st.form_submit_button("Simpan penilaian")
            if rubric_save:
                if not rater.strip():
                    st.error("Kode penilai wajib diisi.")
                else:
                    STORE.update(rubric_id, {
                        "rubric_evidence": score_evidence, "rubric_recommendation": score_reco,
                        "rubric_rater": rater.strip(), "rubric_note": rubric_note.strip(),
                    })
                    st.success("Penilaian disimpan.")
                    st.rerun()

        st.markdown("#### Data trial")
        if all_trials:
            st.dataframe([{k: ("; ".join(v) if isinstance(v, list) else v) for k, v in t.items() if k in CSV_FIELDS} for t in all_trials])
            export_col1, export_col2 = st.columns(2)
            with export_col1:
                st.download_button("Unduh CSV (tanpa teks laporan)", trials_to_csv(all_trials), "trials.csv", "text/csv", key="dl_trials_csv")
            with export_col2:
                st.download_button("Unduh JSONL (lengkap, untuk cadangan)", "".join(json.dumps(t, ensure_ascii=False) + "\n" for t in all_trials), "trials.jsonl", "application/json", key="dl_trials_jsonl")
        else:
            st.info("Belum ada trial tercatat.")
        restore_file = st.file_uploader("Pulihkan dari JSONL", type=["jsonl", "json", "txt"], key="trial_restore")
        if st.button("Gabungkan data", key="trial_restore_btn"):
            if restore_file is None:
                st.error("Pilih berkas JSONL terlebih dahulu.")
            else:
                added, skipped = STORE.import_text(restore_file.getvalue().decode("utf8", errors="replace"))
                st.success(f"{added} trial ditambahkan, {skipped} baris dilewati (id sudah ada atau rusak).")
                st.rerun()


# ==========================================
# TAB: HISTORY (RIWAYAT ANALISIS)
# ==========================================
with tab_history:
    st.subheader("Riwayat Analisis")
    st.markdown("Data riwayat di bawah ini disimpan sementara dan akan hilang jika Anda refresh halaman.")
    
    if len(st.session_state.history) == 0:
        st.info("Belum ada riwayat analisis.")
    else:
        # Tombol untuk menghapus riwayat
        if st.button("Hapus Semua Riwayat"):
            st.session_state.history = []
            st.rerun() # Refresh halaman agar riwayat bersih
            
        st.markdown("---")
        
        # Menampilkan setiap riwayat dalam bentuk expander (bisa di-klik untuk buka/tutup)
        for item in st.session_state.history:
            with st.expander(f"[{item['timestamp']}] {item['ioc']} - {item['status']} | AI: {item.get('ai_verdict', '-')}"):
                st.write(f"**Alert Name:** {item['alert_name']}")
                st.write(f"**Mode:** {item.get('mode', '-')} | **Pembanding:** {item.get('match_label', '-')} | **Verifikasi SSL:** {'aktif' if item.get('tls_verify', True) else 'mati'} | **AI:** {item.get('llm_provider', '-')} ({item.get('llm_model', '-')})")
                if item.get('cti_log'):
                    st.table(item['cti_log'])
                st.text_area(
                    "Final Report", 
                    value=item['report'], 
                    height=250, 
                    key=f"report_{item['timestamp']}" # Menggunakan waktu sebagai key unik
                )
                
                st.download_button(
                    label="Download Prompt Text",
                    data=item['raw_prompt'],
                    file_name=f"history_prompt_{item['ioc'].replace('.', '_')}.txt",
                    mime="text/plain",
                    key=f"dl_{item['timestamp']}" # Menggunakan waktu sebagai key unik
                )

# ==========================================
# TAB: AUTOMATION (EXTRACT & DEFANG IoC)
# ==========================================
with tab_defang:
    st.subheader("Clean IoC Extractor & Defang")
    st.markdown("Ekstrak IP, URL, dan Domain otomatis.")
    
    raw_ioc_input = st.text_area(
        "Insert (Raw Logs / SIEM Dump):", 
        placeholder="Contoh:\nDns: wildan.vercel.app\nUrl: https://www.google.com/\nIp: 192.168.1.1\n...",
        height=300
    )
    
    def extract_and_defang_mixed_iocs(text):
        # 1. Buang label metadata log agar tidak ikut terdeteksi
        cleanup_labels = ['System:', 'Ip:', 'Dns:', 'Url:', 'Domain:']
        clean_text = text
        for label in cleanup_labels:
            clean_text = re.sub(f'(?i){label}', ' ', clean_text)
            
        # 2. Pisahkan teks berdasarkan spasi, koma, tanda kutip ("), atau backslash (\)
        # Ini akan otomatis membuang backslash (\) dan memisahkan array URL yang tergabung
        tokens = re.split(r'[\s,\"\'\\]+', clean_text)
        
        unique_iocs = set() # Menggunakan Set otomatis mencegah duplikat
        
        # Pola deteksi IP dan Domain/URL dasar
        ip_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
        domain_url_pattern = re.compile(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        
        for token in tokens:
            token = token.strip()
            if not token:
                continue
            
            # 3. Filter/Bersihkan protokol dan www
            token = re.sub(r'^https?://', '', token, flags=re.IGNORECASE) # Buang http:// atau https://
            token = re.sub(r'^www\.', '', token, flags=re.IGNORECASE)     # Buang www.
            token = token.strip('/')                                      # Buang slash (/) nyasar di awal/akhir
            
            if not token:
                continue
                
            # 4. Validasi & Defang
            # Jika itu adalah IP atau mengandung format Domain
            if ip_pattern.match(token) or domain_url_pattern.search(token):
                defanged_ioc = token.replace(".", "[.]")
                unique_iocs.add(defanged_ioc)

        # 5. Urutkan abjad & gabungkan dengan enter murni (tanpa gap)
        sorted_iocs = sorted(list(unique_iocs))
        return "\n".join(sorted_iocs)

    if st.button("Extract & Clean Defang", type="primary"):
        if raw_ioc_input.strip():
            with st.spinner("Memproses dan membersihkan data..."):
                defanged_output = extract_and_defang_mixed_iocs(raw_ioc_input)
                
                if defanged_output:
                    # Menghitung jumlah IoC menggunakan line count
                    ioc_count = len(defanged_output.split('\n'))
                    st.success(f"Berhasil! Menemukan {ioc_count} indikator unik yang bersih.")
                    st.text_area("Hasil :", value=defanged_output, height=350)
                else:
                    st.warning("Tidak ditemukan IP, URL, atau Domain yang valid pada teks yang diberikan.")
        else:
            st.error("Masukkan teks mentah terlebih dahulu di kotak atas.")

# ==========================================
# TAB: SHIFT HANDOVER SUMMARIZER
# ==========================================
with tab_shift:
    st.subheader("Shift Handover Summarizer")
    st.markdown("Otomatis mengekstrak raw log tiket shift menjadi format template End of Shift Report.")
    
    raw_shift_input = st.text_area(
        "Masukkan Raw Data (Copy-paste):", 
        height=300,
        placeholder="250666-2722\n250666/ApplicationGateway/...\n..."
    )
    
    def parse_shift_logs(raw_text):
        lines = [line.strip() for line in raw_text.split('\n') if line.strip()]
        summaries = []
        
        for i, line in enumerate(lines):
            # 1. Deteksi Baris Tiket Baru
            if '/' in line and len(line.split('/')) >= 3:
                parts = line.split('/')
                
                # --- 0. REPAIR N/A SPLIT ---
                if len(parts) >= 2 and parts[-2].strip() == 'N' and parts[-1].strip().startswith('A'):
                    parts[-2] = "N/A" + parts[-1][1:]
                    parts.pop()
                    
                incident_id = "N/A"
                alert_name = "N/A"
                action = "Blocked"  
                workspace = "N/A"
                status = "Attempt"
                ticket_state = "Closed" # Default
                
                # --- 1. EKSTRAK INCIDENT ID (Ambil dari baris atasnya) ---
                if i > 0 and re.search(r'([A-Za-z0-9]+-\d{3,5})', lines[i-1]):
                    id_match = re.search(r'([A-Za-z0-9]+-\d{3,5})', lines[i-1])
                    incident_id = id_match.group(1).strip()
                else:
                    # Fallback jika kebetulan masih menempel
                    fallback_match = re.search(r'([A-Za-z0-9]+-\d{3,5})', parts[0])
                    if fallback_match:
                        incident_id = fallback_match.group(1).strip()
                        
                # --- 2. EKSTRAK ALERT NAME (Mencari Batas Severity dari Belakang) ---
                severity_levels = ["Low", "Medium", "High", "Critical", "Informational", "-"]
                sev_index = -1
                
                for j in range(len(parts)-1, 1, -1):
                    if parts[j].strip() in severity_levels:
                        sev_index = j
                        break
                
                if sev_index != -1:
                    alert_name = "/".join(parts[2:sev_index]).strip()
                else:
                    alert_name = "/".join(parts[2:-2]).strip() if len(parts) >= 5 else parts[2].strip()
                    
                alert_name = re.sub(r'[\[\]\"\\]', '', alert_name).strip()
                if alert_name == "-":
                    alert_name = "Unknown / No Alert Name"
                    
                # --- 3. EKSTRAK ACTION & WORKSPACE ---
                raw_action = parts[-1].strip()
                temp_action = re.sub(r'[\[\]\"\\]', '', raw_action).strip()
                
                words = temp_action.split()
                if len(words) > 1 and any(ws in words[-1].lower() for ws in ['-sentinel', 'compnet', 'namicoh', 'bquik', 'maps']):
                    workspace = words[-1]
                    temp_action = " ".join(words[:-1]).strip()
                
                if temp_action.upper() not in ["N/A", "N", "-", ""]:
                    action = temp_action.capitalize() if temp_action.isalpha() and temp_action.islower() else temp_action
                        
                # --- 4. FALLBACK WORKSPACE ---
                if workspace == "N/A" and i + 1 < len(lines):
                    next_line = lines[i+1]
                    if not ('/' in next_line and len(next_line.split('/')) >= 3):
                        workspace = next_line.split()[0]
                
                if alert_name != "N/A":
                    summaries.append({
                        "incident_id": incident_id,
                        "workspace": workspace,
                        "alert_name": alert_name,
                        "action": action,
                        "status": status,
                        "ticket_state": ticket_state
                    })
            
            # --- 5. UPDATE FLAG STATUS & STATE ---
            if summaries:
                if "INCIDENT OPEN" in line.upper():
                    summaries[-1]["ticket_state"] = "Open"
                elif "INCIDENT CLOSED" in line.upper():
                    summaries[-1]["ticket_state"] = "Closed"
                    
                if "TruePositive" in line:
                    summaries[-1]["status"] = "Incident"
                elif "BenignPositive" in line:
                    summaries[-1]["status"] = "Attempt"
                    
        return summaries

    if st.button("Generate Shift Summary", type="primary"):
        if raw_shift_input.strip():
            with st.spinner("Merangkum data shift ke dalam template..."):
                parsed_data = parse_shift_logs(raw_shift_input)
                
                if not parsed_data:
                    st.warning("Tidak ada data log yang valid ditemukan.")
                else:
                    incidents = [s for s in parsed_data if s["status"] == "Incident"]
                    attempts = [s for s in parsed_data if s["status"] == "Attempt"]
                    
                    # Logika Kalkulasi (Active dikunci 0 jika instruksi sebelumnya masih berlaku)
                    active_count = 0 
                    closed_count = len(parsed_data)
                    
                    output_text = "End of Shift Report\n\n"
                    output_text += "✅ Analyst: M. Wildan\n"
                    output_text += "✅ Shift: 07:30-19:30 / 19:30-07:30 / 20:00-08:00\n"
                    output_text += "✅ Incident Summary:\n"
                    output_text += f"    ✅ Active: {active_count}\n"
                    output_text += f"    ✅ Closed: {closed_count}\n"
                    output_text += f"    ✅ Attempts: {len(attempts)}\n"
                    output_text += f"    ✅ Incidents: {len(incidents)}\n"
                    output_text += "    ✅ Escalated: 0\n"
                    output_text += "    ✅ Change Requests: 0\n\n"
                    
                    output_text += "======================================\n\n"
                    
                    if incidents:
                        output_text += "Incidents :\n\n"
                        for idx, item in enumerate(incidents):
                            output_text += f"Incident ID (Azure): {item['incident_id']}\n"
                            output_text += f"Workspace: {item['workspace']}\n"
                            output_text += f"Alert Name: {item['alert_name']}\n"
                            output_text += f"Critical Assets: No\n"
                            output_text += f"Device Action: {item['action']}\n"
                            
                            if idx < len(incidents) - 1 or attempts:
                                output_text += "\n"
                    
                    if attempts:
                        output_text += "Attempts :\n\n"
                        for idx, item in enumerate(attempts):
                            output_text += f"Incident ID (Azure): {item['incident_id']}\n"
                            output_text += f"Workspace: {item['workspace']}\n"
                            output_text += f"Alert Name: {item['alert_name']}\n"
                            output_text += f"Critical Assets: No\n"
                            output_text += f"Device Action: {item['action']}\n"
                            
                            if idx < len(attempts) - 1:
                                output_text += "\n"
                    
                    st.success(f"Berhasil menyusun Laporan End of Shift!")
                    st.text_area(
                        "Plaintext Handover Output (Siap Copy-Paste):", 
                        value=output_text, 
                        height=500
                    )
                    
                    st.download_button(
                        label="Download Rangkuman (.txt)",
                        data=output_text,
                        file_name=f"End_Of_Shift_Wildan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                        mime="text/plain"
                    )
        else:
            st.error("Masukkan raw data shift terlebih dahulu di kotak atas.")
