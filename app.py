import streamlit as st
import re
import requests
import json
import urllib3
from datetime import datetime, timezone
from google import genai 
from google.genai import types
from ioc_extract import extract_iocs, pick_primary, first_public_ip

# --- MENCEGAH WARNING SSL MUNZUL DI TERMINAL ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- KONSTANTA & PROMPT ---
SOC_ANALYST_ROLE = """
You are a 'SOC Analyst'. Your primary role is to analyze potential threats based on provided data. Your goal is to provide a clear, concise, and actionable report.

Behaviors and Rules:
1) Initial Data Review: Correlate all provided context.
2) Threat Analysis and Report Generation:
a) You MUST present your findings using the exact template below. Do not add, remove, or re-order sections.
b) CRITICAL: You MUST defang all domains in your final generated report by replacing each period '.' with '[.]'. For example, write 'example.com' as 'example[.]com'. DO NOT defang IP addresses.
c) If tools like URLScan or HybridAnalysis are not present or return errors/no data, you MUST state "N/A".
d) DO NOT use any markdown formatting (like asterisks or hashes) in the output. Keep it plain text.

--- REPORT TEMPLATE ---
1. INDICATOR OF COMPROMISE (IoC)
IoC: [The primary IoC, defanged if domain]
IoC Type: [IP, Domain, MD5, SHA1, or SHA256]
First Seen: [Date or N/A]
Last Seen: [Date or N/A]

2. ALERT CONTEXT
Alert Name: [Name of the alert]
Action Taken: [Action taken, e.g., Blocked]
Initial Verdict: [The initial verdict provided in the data]

3. THREAT ANALYSIS
Domain/IP/hash: [The primary IoC, defanged if domain]
URLScan: [Summary of URLScan data, or "N/A"]
VirusTotal: [Summary of VirusTotal detections, e.g., 7/93, and key relationship findings]
AbuseIPDB: [Summary of AbuseIPDB confidence score and reports based on the related IP, or "N/A"]
HybridAnalysis: [Summary of HybridAnalysis data, or "N/A"]

Conclusion: [A brief conclusive sentence based purely on the findings from the tools above.]

4. DESCRIPTION
[Synthesize the alert details and threat intel into a clear narrative explaining the threat. Assess the potential risk and explain WHAT this threat actually does based on the evidence.]

5. RECOMMENDATIONS
[Actionable step 1]
[Actionable step 2]
[Actionable step 3]

6. SUMMARY
[Summarize the entire analysis and recommended action in 1-2 clear, concise sentences.]
--- END OF TEMPLATE ---
"""

# --- FUNGSI HELPER & API ---
def defang_ioc(ioc_string, ioc_type):
    if ioc_type == 'domain' and isinstance(ioc_string, str):
        return ioc_string.replace('.', '[.]')
    return ioc_string

def get_ioc_type(ioc):
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ioc): return "ip"
    if re.match(r"^[a-fA-F0-9]{32}$", ioc): return "md5"
    if re.match(r"^[a-fA-F0-9]{40}$", ioc): return "sha1"
    if re.match(r"^[a-fA-F0-9]{64}$", ioc): return "sha256"
    if '.' in ioc and not ' ' in ioc: return "domain"
    return "unknown"

def tls_verify():
    """Verifikasi sertifikat SSL aktif secara default. Hanya mati jika analis mematikannya di sidebar."""
    return st.session_state.get("tls_verify", True)

def query_virustotal(ioc, ioc_type, api_key):
    if not api_key: return '{"error": "VirusTotal API key not configured."}'
    if ioc_type == "ip": url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc_type in ["md5", "sha1", "sha256"]: url = f"https://www.virustotal.com/api/v3/files/{ioc}"
    elif ioc_type == "domain": url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
    else: return '{"error": "Unsupported IoC type."}'
    try:
        response = requests.get(url, headers={"x-apikey": api_key}, timeout=15, verify=tls_verify())
        response.raise_for_status()
        return json.dumps(response.json().get("data", {}).get("attributes", {}), indent=2)
    except Exception as e: return f'{{"error": "{str(e)}"}}'

def query_virustotal_relationships(ioc, ioc_type, api_key):
    if not api_key: return {}
    base_urls = {"ip": f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}/", "domain": f"https://www.virustotal.com/api/v3/domains/{ioc}/", "file": f"https://www.virustotal.com/api/v3/files/{ioc}/"}
    endpoints_map = {"ip": ["resolutions", "communicating_files"], "domain": ["resolutions", "communicating_files"], "file": ["contacted_domains", "contacted_ips", "execution_parents"]}
    ioc_key = "file" if ioc_type in ["md5", "sha1", "sha256"] else ioc_type
    if ioc_key not in base_urls: return {}
    relationship_data = {}
    for endpoint in endpoints_map[ioc_key]:
        try:
            response = requests.get(base_urls[ioc_key] + endpoint, headers={"x-apikey": api_key}, params={'limit': 10}, timeout=15, verify=tls_verify())
            response.raise_for_status()
            relationship_data[endpoint] = response.json().get("data", [])
        except Exception as e: relationship_data[endpoint] = {"error": str(e)}
    return relationship_data

def query_abuseipdb(ip, api_key):
    if not ip: return ""
    if not api_key: return '{"error": "AbuseIPDB API key not configured."}'
    try:
        response = requests.get("https://api.abuseipdb.com/api/v2/check", headers={"Accept": "application/json", "Key": api_key}, params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""}, timeout=15, verify=tls_verify())
        response.raise_for_status()
        return json.dumps(response.json().get("data", {}), indent=2)
    except Exception as e: return f'{{"error": "{str(e)}"}}'

def query_tip_neiki(ioc, ioc_type):
    if ioc_type not in ["md5", "sha1", "sha256"]: return ""
    try:
        response = requests.get(f"https://tip.neiki.dev/api/reports/file/{ioc}", timeout=30, verify=tls_verify())
        response.raise_for_status()
        return json.dumps(response.json(), indent=2)
    except Exception as e: return f'{{"error": "{str(e)}"}}'

def query_urlscan(ioc, ioc_type, api_key):
    if not api_key: return '{"error": "URLScan API key not configured."}'
    if ioc_type not in ['domain', 'ip']: return ""
    try:
        headers = {'API-Key': api_key, 'Content-Type': 'application/json'}
        query_val = f"domain:{ioc}" if ioc_type == "domain" else f"ip:{ioc}"
        response = requests.get(f"https://urlscan.io/api/v1/search/?q={query_val}", headers=headers, timeout=15, verify=tls_verify())
        response.raise_for_status()
        results = response.json().get('results', [])
        if results:
            top_result = results[0]
            summary = {"latest_scan_url": top_result.get('result'), "verdicts": top_result.get('verdicts', {}), "task_time": top_result.get('task', {}).get('time')}
            return json.dumps(summary, indent=2)
        return '{"message": "No previous scans found on URLScan."}'
    except Exception as e: return f'{{"error": "{str(e)}"}}'

def query_hybridanalysis(ioc, ioc_type, api_key):
    if not api_key: return '{"error": "HybridAnalysis API key not configured."}'
    if ioc_type not in ["md5", "sha1", "sha256"]: return ""
    try:
        # Tambahkan Content-Type dan hapus 'www.' pada URL
        headers = {
            'api-key': api_key, 
            'User-Agent': 'Falcon Sandbox',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        response = requests.post("https://hybrid-analysis.com/api/v2/search/hash", headers=headers, data={'hash': ioc}, timeout=15, verify=tls_verify())
        response.raise_for_status()
        results = response.json()
        if results and isinstance(results, list) and len(results) > 0:
            top = results[0]
            summary = {"verdict": top.get("verdict"), "threat_score": top.get("threat_score"), "environment": top.get("environment_description")}
            return json.dumps(summary, indent=2)
        return '{"message": "No reports found on HybridAnalysis."}'
    except Exception as e: return f'{{"error": "{str(e)}"}}'

def generate_initial_verdict(ioc_type, vt_data_str, abuse_data_str):
    verdict, reasons = "Likely Benign", []
    try: vt_data = json.loads(vt_data_str)
    except: vt_data = {}
    try: abuse_data = json.loads(abuse_data_str) if abuse_data_str else {}
    except: abuse_data = {}
    
    if ioc_type in ["md5", "sha1", "sha256"]:
        malicious = vt_data.get("last_analysis_stats", {}).get("malicious", 0)
        if 0 < malicious < 10: verdict, reasons = "False Positive", [f"VT: {malicious} (<10)"]
        elif malicious >= 10: verdict, reasons = "Likely Malicious", [f"VT: {malicious} (>=10)"]
    elif ioc_type == 'ip':
        conf = abuse_data.get("abuseConfidenceScore", -1)
        if conf == 0: verdict, reasons = "False Positive", ["AbuseIPDB: 0%"]
        elif conf > 0: verdict, reasons = "Likely Malicious", [f"AbuseIPDB: {conf}%"]
        malicious = vt_data.get("last_analysis_stats", {}).get("malicious", 0)
        if malicious > 0: reasons.append(f"VT: {malicious}")
    elif ioc_type == 'domain':
        malicious = vt_data.get("last_analysis_stats", {}).get("malicious", 0)
        if malicious > 4: verdict, reasons = "Likely Malicious", [f"VT: {malicious}"]
        elif malicious > 0: verdict, reasons = "Suspicious", [f"VT: {malicious}"]

    if not reasons: return "Likely Benign (No negative indicators found)"
    return f"{verdict} ({'; '.join(reasons)})"

def parse_ai_verdict(report_text):
    """Baca verdict AI dari baris Conclusion. Mengembalikan 'Tidak terbaca' jika formatnya tidak ditemukan."""
    match = re.search(r"Conclusion:\s*[\"'\[]?\s*(True Positive|False Positive|Likely Benign)", report_text or "", re.IGNORECASE)
    if not match:
        return "Tidak terbaca"
    return {"true positive": "True Positive", "false positive": "False Positive", "likely benign": "Likely Benign"}[match.group(1).lower()]

def summarize_cti(source, result):
    """Ringkas hasil satu sumber CTI menjadi (status, temuan utama)."""
    if not result:
        return "Dilewati", "Tidak berlaku untuk tipe IoC ini"
    if isinstance(result, dict):  # relationships VirusTotal
        errors = [f"{k}: {v['error']}" for k, v in result.items() if isinstance(v, dict) and "error" in v]
        counts = ", ".join(f"{k}: {len(v)}" for k, v in result.items() if isinstance(v, list))
        if errors and not counts:
            return "Gagal", "; ".join(errors)[:140]
        return "OK", counts or "Tidak ada relasi"
    try:
        data = json.loads(result)
    except Exception:
        return "Gagal", "Respons bukan JSON"
    if "error" in data:
        return "Gagal", str(data["error"])[:140]
    if list(data.keys()) == ["message"]:
        return "Tidak ada data", str(data["message"])
    if source == "VirusTotal":
        stats = data.get("last_analysis_stats", {})
        return "OK", f"malicious {stats.get('malicious', 0)} dari {sum(stats.values()) or '?'} engine"
    if source == "AbuseIPDB":
        return "OK", f"confidence {data.get('abuseConfidenceScore', '?')}%, laporan {data.get('totalReports', '?')}"
    if source == "URLScan":
        overall = data.get("verdicts", {}).get("overall", {})
        return "OK", f"verdict overall malicious={overall.get('malicious', '?')}, score={overall.get('score', '?')}"
    if source == "HybridAnalysis":
        return "OK", f"verdict {data.get('verdict', '?')}, threat_score {data.get('threat_score', '?')}"
    return "OK", "Data diterima"

def run_cti(log, source, queried, applicable, fn, *args):
    """Jalankan satu query CTI dan catat sumber, nilai yang di-query, waktu UTC, status, dan temuan utama."""
    if not applicable:
        log.append({"Sumber": source, "Query": queried, "Waktu (UTC)": "n/a", "Status": "Dilewati", "Temuan": "Tidak berlaku untuk tipe IoC ini"})
        return ""
    result = fn(*args)
    status, finding = summarize_cti(source, result)
    log.append({
        "Sumber": source,
        "Query": queried,
        "Waktu (UTC)": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "Status": status,
        "Temuan": finding,
    })
    return result

def generate_prompt(alert_name, ioc, ioc_type, action, collated_data, initial_verdict, first_seen, last_seen, final_verdict_decision=None):
    # final_verdict_decision=None berarti mode Blind: status analis tidak boleh sampai ke AI.
    if final_verdict_decision:
        verdict_instruction = f"It is a {final_verdict_decision}, please make the draft accordingly in blockcode without any text formatting and without any cite in domain related to gambling/pornography/red website website."
    else:
        verdict_instruction = (
            "No analyst verdict is provided. Decide the verdict yourself, using only the data above: True Positive, False Positive, or Likely Benign. "
            "Start the Conclusion line in section 3 with exactly that verdict followed by a period, for example 'Conclusion: False Positive. ...'. "
            "Then make the draft accordingly in blockcode without any text formatting and without any cite in domain related to gambling/pornography/red website website."
        )
    return f"""{SOC_ANALYST_ROLE}

--- START OF DATA ---
Alert Name: {alert_name}
Action Taken: {action if action else "N/A"}
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

# --- INISIALISASI SESSION STATE UNTUK HISTORY ---
if "history" not in st.session_state:
    st.session_state.history = []

# --- UI STREAMLIT ---
st.set_page_config(page_title="SOC Threat Intel @wildaan", page_icon="🛡️", layout="wide")

# --- TEMA (hanya tampilan, lihat theme.py dan .streamlit/config.toml) ---
from theme import apply_theme
apply_theme()

st.title("🛡️ SOC Threat Inteligence Dashboard")
st.markdown("Automation gathering threat Inteligence and report @wildaaan.")

# --- AMBIL DATA DARI STREAMLIT SECRETS (Dengan Penanganan Error Lanjutan) ---
ENV_GEMINI = ""
ENV_VT = ""
ENV_ABUSE = ""
ENV_URLSCAN = ""
ENV_HYBRID = ""

try:
    ENV_GEMINI = st.secrets.get("GEMINI_API_KEY", "")
    ENV_VT = st.secrets.get("VT_API_KEY", "")
    ENV_ABUSE = st.secrets.get("ABUSEIPDB_API_KEY", "")
    ENV_URLSCAN = st.secrets.get("URLSCAN_API_KEY", "")
    ENV_HYBRID = st.secrets.get("HYBRID_API_KEY", "")
except:
    pass # Jika secrets.toml tidak ada di lokal, biarkan kosong

# --- SIDEBAR KONFIGURASI API ---
st.sidebar.header("Konfigurasi API")
gemini_key = st.sidebar.text_input("Gemini API Key (Wajib)", type="password", value=ENV_GEMINI)
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

# --- MEMBAGI UI MENJADI 3 TAB ---
tab1, tab2, tab3, tab4, tab5 = st.tabs(["New Analysis", "History", "Defang", "Converter", "Shift Summarizer"])

# ==========================================
# TAB 1: NEW ANALYSIS
# ==========================================
MODE_BLIND = "Blind: AI menilai sendiri (untuk pengujian)"
MODE_ASSISTED = "Dibantu: status analis dikirim ke AI"

with tab1:
    with st.form("ioc_form"):
        col1, col2 = st.columns(2)
        with col1:
            alert_name = st.text_input("Alert Name:", placeholder="e.g., FGT utm:webfilter blocked")
            ioc = st.text_input("Primary IoC (kosong = ambil dari Raw Alert):", placeholder="IP, Domain, MD5, SHA1, atau SHA256")
            final_verdict_decision = st.selectbox("Status Alert (keputusan analis / ground truth):", ["Belum ditentukan", "True Positive", "False Positive", "Likely Benign"])
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
        extracted_iocs = extract_iocs(raw_alert)
        ioc = ioc.strip() or (pick_primary(extracted_iocs) or "")
        analyst_status = None if final_verdict_decision == "Belum ditentukan" else final_verdict_decision

        if not alert_name or not ioc:
            st.error("Alert Name dan Primary IoC wajib diisi (atau tempel Raw Alert yang berisi IoC publik)!")
        elif analysis_mode == MODE_ASSISTED and analyst_status is None:
            st.error("Mode Dibantu butuh Status Alert. Pilih statusnya, atau ganti ke mode Blind.")
        elif not vt_key or not abuse_key or not gemini_key:
            st.error("Harap masukkan Gemini, VirusTotal, dan AbuseIPDB API Key di menu Sidebar terlebih dahulu.")
        else:
            ioc_type = get_ioc_type(ioc)

            if ioc_type == "unknown":
                st.error(f"Tidak dapat mendeteksi tipe IoC untuk: '{ioc}'. Pastikan formatnya benar.")
            else:
                with st.spinner(f"1/2: Mengambil data intel untuk {ioc_type.upper()} {defang_ioc(ioc, ioc_type)}..."):
                    target_ip_for_abuse = ioc if ioc_type == 'ip' else (abuse_ip.strip() or first_public_ip(extracted_iocs) or "")
                    is_hash = ioc_type in ["md5", "sha1", "sha256"]
                    cti_log = []

                    vt_results = run_cti(cti_log, "VirusTotal", ioc, True, query_virustotal, ioc, ioc_type, vt_key)
                    vt_rel_results = run_cti(cti_log, "VirusTotal (relationships)", ioc, True, query_virustotal_relationships, ioc, ioc_type, vt_key)
                    abuse_results = run_cti(cti_log, "AbuseIPDB", target_ip_for_abuse or "n/a", bool(target_ip_for_abuse), query_abuseipdb, target_ip_for_abuse, abuse_key)
                    urlscan_results = run_cti(cti_log, "URLScan", ioc, ioc_type in ['domain', 'ip'], query_urlscan, ioc, ioc_type, urlscan_key)
                    hybrid_results = run_cti(cti_log, "HybridAnalysis", ioc, is_hash, query_hybridanalysis, ioc, ioc_type, hybrid_key)
                    tip_results = run_cti(cti_log, "TIP Neiki", ioc, is_hash, query_tip_neiki, ioc, ioc_type)

                    first_seen, last_seen = "N/A", "N/A"
                    try:
                        vt_dict = json.loads(vt_results)
                        if vt_dict.get('last_analysis_date'):
                            last_seen = datetime.fromtimestamp(vt_dict['last_analysis_date']).strftime('%Y-%m-%d %H:%M:%S UTC')
                    except: pass

                    verdict = generate_initial_verdict(ioc_type, vt_results, abuse_results)

                    collated = f"VirusTotal Data:\n{vt_results}\n"
                    if vt_rel_results: collated += f"\nVirusTotal Relationships:\n{json.dumps(vt_rel_results, indent=2)}\n"
                    if abuse_results: collated += f"\nAbuseIPDB Data:\n{abuse_results}\n"
                    if urlscan_results: collated += f"\nURLScan Data:\n{urlscan_results}\n"
                    if hybrid_results: collated += f"\nHybridAnalysis Data:\n{hybrid_results}\n"
                    if tip_results: collated += f"\nTIP Neiki Data:\n{tip_results}\n"

                    # Hanya IoC hasil ekstraksi yang ikut ke prompt. Teks Raw Alert tidak dikirim ke AI.
                    other_iocs = [i for i in extracted_iocs if i["value"] != ioc]
                    if other_iocs:
                        collated += "\nOther IoCs extracted from the alert (not enriched):\n"
                        collated += "\n".join(f"- {i['type']}: {i['value']}" + ("" if i["public"] else " (private/non-routable)") for i in other_iocs) + "\n"
                    collated += "\nCTI Retrieval Log (UTC):\n"
                    collated += "\n".join(f"- {r['Sumber']} | query: {r['Query']} | {r['Waktu (UTC)']} | {r['Status']}: {r['Temuan']}" for r in cti_log) + "\n"

                    # Mode Blind: status analis tidak dikirim ke AI (None).
                    prompt_status = final_verdict_decision if analysis_mode == MODE_ASSISTED else None
                    final_prompt = generate_prompt(alert_name, ioc, ioc_type, action, collated, verdict, first_seen, last_seen, prompt_status)

                with st.spinner("2/2: Menghasilkan Laporan Akhir dengan Gemini AI..."):
                    try:
                        if tls_verify():
                            client = genai.Client(api_key=gemini_key)
                        else:
                            # Verifikasi SSL dimatikan analis lewat sidebar; pilihan ini dicatat di history.
                            import ssl
                            custom_ssl_context = ssl.create_default_context()
                            custom_ssl_context.check_hostname = False
                            custom_ssl_context.verify_mode = ssl.CERT_NONE
                            client = genai.Client(
                                api_key=gemini_key,
                                http_options=types.HttpOptions(client_args={'verify': custom_ssl_context})
                            )
                        response = client.models.generate_content(
                            model='gemini-2.5-flash',
                            contents=final_prompt,
                        )
                        final_report_text = response.text
                    except Exception as e:
                        final_report_text = f"Terjadi kesalahan saat menghubungi API Gemini: {str(e)}"

                # --- BANDINGKAN VERDICT AI DENGAN STATUS ANALIS (setelah AI menjawab) ---
                is_blind = analysis_mode == MODE_BLIND
                ai_verdict = parse_ai_verdict(final_report_text) if is_blind else "-"
                if not is_blind:
                    match_label = "Tidak dinilai (mode Dibantu)"
                elif analyst_status is None:
                    match_label = "Tidak ada pembanding"
                elif ai_verdict == "Tidak terbaca":
                    match_label = "Verdict AI tidak terbaca"
                else:
                    match_label = "Cocok" if ai_verdict == analyst_status else "Tidak cocok"

                st.success(f"Analisis Selesai!")

                # --- SIMPAN KE HISTORY ---
                # Menggunakan .insert(0, ...) agar riwayat terbaru selalu muncul paling atas
                st.session_state.history.insert(0, {
                    "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "ioc": ioc,
                    "alert_name": alert_name,
                    "status": final_verdict_decision,
                    "report": final_report_text,
                    "raw_prompt": final_prompt,
                    "mode": analysis_mode,
                    "ai_verdict": ai_verdict,
                    "match_label": match_label,
                    "tls_verify": tls_verify(),
                    "cti_log": cti_log,
                })

                # Sumber CTI dan waktu pengambilan selalu terlihat oleh analis
                st.subheader("Sumber CTI & Waktu Pengambilan")
                st.table(cti_log)

                cert_failed = any(
                    "certificate_verify_failed" in str(r).lower()
                    for r in (vt_results, vt_rel_results, abuse_results, urlscan_results, hybrid_results, tip_results, final_report_text)
                )
                if cert_failed:
                    st.warning("Verifikasi sertifikat SSL gagal. Jika jaringan Anda memakai SSL inspection, arahkan REQUESTS_CA_BUNDLE dan SSL_CERT_FILE ke CA perusahaan, atau matikan 'Verifikasi sertifikat SSL' di sidebar (pilihan ini dicatat di riwayat).")

                if extracted_iocs:
                    st.subheader("IoC Hasil Ekstraksi")
                    st.table([{
                        "IoC": i["value"],
                        "Tipe": i["type"],
                        "Publik": "ya" if i["public"] else "tidak (tidak diperkaya)",
                        "Peran": "Primary" if i["value"] == ioc else ("Related IP" if i["value"] == target_ip_for_abuse else "Konteks"),
                    } for i in extracted_iocs])

                if is_blind:
                    verdict_summary = f"Verdict AI: {ai_verdict} | Status analis: {analyst_status or 'Belum ditentukan'} | {match_label}"
                    if match_label == "Cocok":
                        st.success(verdict_summary)
                    elif match_label == "Tidak cocok":
                        st.warning(verdict_summary)
                    else:
                        st.info(verdict_summary)
                else:
                    st.info("Mode Dibantu: status analis ikut dikirim ke AI, jadi hasil ini tidak boleh dipakai untuk mengukur ketepatan penilaian AI.")

                # Menampilkan Laporan Akhir
                st.subheader("Final Report :")
                st.text_area("Copy atau edit teks di bawah ini:", value=final_report_text, height=400)

                # --- Tombol Download Prompt Mentah (Fallback) ---
                filename = f"prompt_{ioc.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                st.download_button(
                    label=f"Download Exported File: {filename}",
                    data=final_prompt,
                    file_name=filename,
                    mime="text/plain"
                )
                st.markdown("Generate the report based on the data and follow the template and rules exactly. Execute based on the data given and also refer to the initial verdict. It is a true positive, please make the draft accordingly in blockcode without any text formatting and without any cite in domain related to gambling/pornography/red website website")
                st.markdown("<br>", unsafe_allow_html=True)

                # Tampilkan Data Mentah
                with st.expander("See Raw JSON Data"):
                    st.code(collated, language='json')


# ==========================================
# TAB 2: HISTORY (RIWAYAT ANALISIS)
# ==========================================
with tab2:
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
                st.write(f"**Mode:** {item.get('mode', '-')} | **Pembanding:** {item.get('match_label', '-')} | **Verifikasi SSL:** {'aktif' if item.get('tls_verify', True) else 'mati'}")
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
# TAB 3: AUTOMATION (EXTRACT & DEFANG IoC)
# ==========================================
with tab3:
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
# TAB 4: CLOUD DOCUMENT CONVERTER (PDF <-> WORD)
# ==========================================
# with tab4:
#     st.subheader("Cloud Document Converter")
    
#     # Memilih mode konversi
#     convert_mode = st.radio("Type:", ["PDF to Word", "Word to PDF"], key="converter_radio")
    
#     if convert_mode == "PDF to Word":
#         uploaded_pdf = st.file_uploader("Drag & Drop file PDF di sini", type=["pdf"], key="pdf_uploader")
        
#         if uploaded_pdf is not None:
#             if st.button("Konversi ke Word", key="btn_pdf_to_word"):
#                 with st.spinner("memproses konversi..."):
#                     import tempfile
#                     import os
#                     from pdf2docx import Converter
                    
#                     # Simpan file yang diupload ke ruang sementara
#                     with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp_pdf:
#                         tmp_pdf.write(uploaded_pdf.getvalue())
#                         tmp_pdf_path = tmp_pdf.name
                        
#                     output_docx = tmp_pdf_path.replace(".pdf", ".docx")
                    
#                     try:
#                         cv = Converter(tmp_pdf_path)
#                         cv.convert(output_docx)
#                         cv.close()
                        
#                         with open(output_docx, "rb") as file:
#                             st.download_button(
#                                 label="Download Word (.docx)",
#                                 data=file,
#                                 file_name=f"Converted_{uploaded_pdf.name.replace('.pdf', '')}.docx",
#                                 mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
#                             )
#                         st.success("Done!")
#                     except Exception as e:
#                         st.error(f"Terjadi kesalahan: {e}")
#                     finally:
#                         if os.path.exists(tmp_pdf_path): os.unlink(tmp_pdf_path)
#                         if os.path.exists(output_docx): os.unlink(output_docx)

#     elif convert_mode == "Word to PDF":
#         st.info("Menggunakan Engine LibreOffice (Linux Cloud Compatibility).")
#         uploaded_docx = st.file_uploader("Drag & Drop file Word (.docx) di sini", type=["docx"], key="docx_uploader")
        
#         if uploaded_docx is not None:
#             if st.button("Konversi ke PDF", key="btn_word_to_pdf"):
#                 with st.spinner("Merender PDF via LibreOffice..."):
#                     import tempfile
#                     import os
#                     import subprocess
                    
#                     # Buat direktori sementara
#                     temp_dir = tempfile.mkdtemp()
#                     tmp_docx_path = os.path.join(temp_dir, "input.docx")
                    
#                     with open(tmp_docx_path, "wb") as f:
#                         f.write(uploaded_docx.getvalue())
                    
#                     try:
#                         # Menjalankan perintah linux untuk konversi
#                         subprocess.run([
#                             "libreoffice", "--headless", "--convert-to", "pdf",
#                             "--outdir", temp_dir, tmp_docx_path
#                         ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        
#                         output_pdf = os.path.join(temp_dir, "input.pdf")
                        
#                         if os.path.exists(output_pdf):
#                             with open(output_pdf, "rb") as file:
#                                 st.download_button(
#                                     label="Download PDF (.pdf)",
#                                     data=file,
#                                     file_name=f"Converted_{uploaded_docx.name.replace('.docx', '')}.pdf",
#                                     mime="application/pdf"
#                                 )
#                             st.success("Done!")
#                         else:
#                             st.error("Gagal membuat PDF. Pastikan 'libreoffice' terinstal di server.")
                            
#                     except Exception as e:
#                         st.error(f"Terjadi kesalahan sistem: {e}")
#                         st.warning("Pastikan Anda sudah menambahkan file 'packages.txt' berisi 'libreoffice' di repository GitHub Anda.")
#                     finally:
#                         if os.path.exists(tmp_docx_path): os.unlink(tmp_docx_path)
#                         if os.path.exists(os.path.join(temp_dir, "input.pdf")): 
#                             os.unlink(os.path.join(temp_dir, "input.pdf"))
#                         os.rmdir(temp_dir)


# ==========================================
# TAB 5: SHIFT HANDOVER SUMMARIZER
# ==========================================
with tab5:
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
