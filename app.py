import streamlit as st
import re
import requests
import json
import urllib3
from datetime import datetime
from google import genai 
from google.genai import types

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

def query_virustotal(ioc, ioc_type, api_key):
    if not api_key: return '{"error": "VirusTotal API key not configured."}'
    if ioc_type == "ip": url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc_type in ["md5", "sha1", "sha256"]: url = f"https://www.virustotal.com/api/v3/files/{ioc}"
    elif ioc_type == "domain": url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
    else: return '{"error": "Unsupported IoC type."}'
    try:
        response = requests.get(url, headers={"x-apikey": api_key}, timeout=15, verify=False)
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
            response = requests.get(base_urls[ioc_key] + endpoint, headers={"x-apikey": api_key}, params={'limit': 10}, timeout=15, verify=False)
            response.raise_for_status()
            relationship_data[endpoint] = response.json().get("data", [])
        except Exception as e: relationship_data[endpoint] = {"error": str(e)}
    return relationship_data

def query_abuseipdb(ip, api_key):
    if not ip: return ""
    if not api_key: return '{"error": "AbuseIPDB API key not configured."}'
    try:
        response = requests.get("https://api.abuseipdb.com/api/v2/check", headers={"Accept": "application/json", "Key": api_key}, params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""}, timeout=15, verify=False)
        response.raise_for_status()
        return json.dumps(response.json().get("data", {}), indent=2)
    except Exception as e: return f'{{"error": "{str(e)}"}}'

def query_tip_neiki(ioc, ioc_type):
    if ioc_type not in ["md5", "sha1", "sha256"]: return ""
    try:
        response = requests.get(f"https://tip.neiki.dev/api/reports/file/{ioc}", timeout=30, verify=False)
        response.raise_for_status()
        return json.dumps(response.json(), indent=2)
    except Exception as e: return f'{{"error": "{str(e)}"}}'

def query_urlscan(ioc, ioc_type, api_key):
    if not api_key: return '{"error": "URLScan API key not configured."}'
    if ioc_type not in ['domain', 'ip']: return ""
    try:
        headers = {'API-Key': api_key, 'Content-Type': 'application/json'}
        query_val = f"domain:{ioc}" if ioc_type == "domain" else f"ip:{ioc}"
        response = requests.get(f"https://urlscan.io/api/v1/search/?q={query_val}", headers=headers, timeout=15, verify=False)
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
        response = requests.post("https://hybrid-analysis.com/api/v2/search/hash", headers=headers, data={'hash': ioc}, timeout=15, verify=False)
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

def generate_prompt(alert_name, ioc, ioc_type, action, collated_data, initial_verdict, first_seen, last_seen, final_verdict_decision):
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
It is a {final_verdict_decision}, please make the draft accordingly in blockcode without any text formatting and without any cite in domain related to gambling/pornography/red website website.
"""

# --- INISIALISASI SESSION STATE UNTUK HISTORY ---
if "history" not in st.session_state:
    st.session_state.history = []

# --- UI STREAMLIT ---
st.set_page_config(page_title="SOC Threat Intel @wildaan", page_icon="🛡️", layout="wide")

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
st.sidebar.header("🔑 Konfigurasi API")
gemini_key = st.sidebar.text_input("Gemini API Key (Wajib)", type="password", value=ENV_GEMINI)
st.sidebar.markdown("---")
vt_key = st.sidebar.text_input("VirusTotal API Key (Wajib)", type="password", value=ENV_VT)
abuse_key = st.sidebar.text_input("AbuseIPDB API Key (Wajib)", type="password", value=ENV_ABUSE)
st.sidebar.markdown("---")
urlscan_key = st.sidebar.text_input("URLScan API Key (Opsional)", type="password", value=ENV_URLSCAN)
hybrid_key = st.sidebar.text_input("HybridAnalysis API Key (Opsional)", type="password", value=ENV_HYBRID)

# --- MEMBAGI UI MENJADI 3 TAB ---
tab1, tab2, tab3, tab4 = st.tabs(["🔍 New Analysis", "🕒 History", "⚙️ Single Defang", "📝 Bulk Parser"])

# ==========================================
# TAB 1: NEW ANALYSIS
# ==========================================
with tab1:
    with st.form("ioc_form"):
        col1, col2 = st.columns(2)
        with col1:
            alert_name = st.text_input("Alert Name:", placeholder="e.g., FGT utm:webfilter blocked")
            ioc = st.text_input("Primary IoC:", placeholder="IP, Domain, MD5, SHA1, atau SHA256")
            final_verdict_decision = st.selectbox("Status Alert (Untuk instruksi AI):", ["True Positive", "False Positive", "Likely Benign"])
        with col2:
            action = st.text_input("Action Taken (Opsional):", placeholder="e.g., Blocked")
            abuse_ip = st.text_input("Related IP untuk AbuseIPDB (Opsional):", placeholder="Masukkan IP jika IoC utama adalah Domain/Hash")
        
        submit_button = st.form_submit_button("Mulai Analisis & Generate Laporan")

    if submit_button:
        if not alert_name or not ioc:
            st.error("⚠️ Alert Name dan Primary IoC wajib diisi!")
        elif not vt_key or not abuse_key or not gemini_key:
            st.error("⚠️ Harap masukkan Gemini, VirusTotal, dan AbuseIPDB API Key di menu Sidebar terlebih dahulu.")
        else:
            ioc = ioc.strip()
            ioc_type = get_ioc_type(ioc)
            
            if ioc_type == "unknown":
                st.error(f"⚠️ Tidak dapat mendeteksi tipe IoC untuk: '{ioc}'. Pastikan formatnya benar.")
            else:
                with st.spinner(f"1/2: Mengambil data intel untuk {ioc_type.upper()} {defang_ioc(ioc, ioc_type)}..."):
                    target_ip_for_abuse = ioc if ioc_type == 'ip' else abuse_ip.strip()

                    vt_results = query_virustotal(ioc, ioc_type, vt_key)
                    vt_rel_results = query_virustotal_relationships(ioc, ioc_type, vt_key)
                    abuse_results = query_abuseipdb(target_ip_for_abuse, abuse_key) if target_ip_for_abuse else ""
                    urlscan_results = query_urlscan(ioc, ioc_type, urlscan_key) if ioc_type in ['domain', 'ip'] else ""
                    hybrid_results = query_hybridanalysis(ioc, ioc_type, hybrid_key) if ioc_type in ["md5", "sha1", "sha256"] else ""
                    tip_results = query_tip_neiki(ioc, ioc_type) if ioc_type in ["md5", "sha1", "sha256"] else ""
                    
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

                    final_prompt = generate_prompt(alert_name, ioc, ioc_type, action, collated, verdict, first_seen, last_seen, final_verdict_decision)

                with st.spinner("2/2: Menghasilkan Laporan Akhir dengan Gemini AI..."):
                    try:
                        # JURUS BYPASS SSL TINGKAT LANJUT
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

                st.success(f"Analisis Selesai!")
                
                # --- SIMPAN KE HISTORY ---
                # Menggunakan .insert(0, ...) agar riwayat terbaru selalu muncul paling atas
                st.session_state.history.insert(0, {
                    "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "ioc": ioc,
                    "alert_name": alert_name,
                    "status": final_verdict_decision,
                    "report": final_report_text,
                    "raw_prompt": final_prompt
                })

                # Menampilkan Laporan Akhir
                st.subheader("📝 Final Report :")
                st.text_area("Copy atau edit teks di bawah ini:", value=final_report_text, height=400)
                
                # --- Tombol Download Prompt Mentah (Fallback) ---
                filename = f"prompt_{ioc.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                st.download_button(
                    label=f"⬇️ Download Exported File: {filename}",
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
    st.subheader("🕒 Riwayat Analisis")
    st.markdown("Data riwayat di bawah ini disimpan sementara dan akan hilang jika Anda refresh halaman.")
    
    if len(st.session_state.history) == 0:
        st.info("Belum ada riwayat analisis.")
    else:
        # Tombol untuk menghapus riwayat
        if st.button("🗑️ Hapus Semua Riwayat"):
            st.session_state.history = []
            st.rerun() # Refresh halaman agar riwayat bersih
            
        st.markdown("---")
        
        # Menampilkan setiap riwayat dalam bentuk expander (bisa di-klik untuk buka/tutup)
        for item in st.session_state.history:
            with st.expander(f"[{item['timestamp']}] {item['ioc']} - {item['status']}"):
                st.write(f"**Alert Name:** {item['alert_name']}")
                st.text_area(
                    "Final Report", 
                    value=item['report'], 
                    height=250, 
                    key=f"report_{item['timestamp']}" # Menggunakan waktu sebagai key unik
                )
                
                st.download_button(
                    label="⬇️ Download Prompt Text",
                    data=item['raw_prompt'],
                    file_name=f"history_prompt_{item['ioc'].replace('.', '_')}.txt",
                    mime="text/plain",
                    key=f"dl_{item['timestamp']}" # Menggunakan waktu sebagai key unik
                )

# ==========================================
# TAB 3: AUTOMATION (DEFANG IoC)
# ==========================================
with tab3:
    st.subheader("⚙️ Defang IoC (Python Automation)")
    
    raw_ioc_input = st.text_area(
        "Masukkan IoC (Bisa copy-paste banyak baris sekaligus):", 
        placeholder="google.com\nwildan.vercel.app\n192.168.1.1\nhttps://evil.com/payload",
        height=200
    )
    
    if st.button("Defang >"):
        if raw_ioc_input.strip():
            # PROSES AUTOMATION PYTHON MURNI
            # 1. Ganti titik menjadi [.]
            defanged_output = raw_ioc_input.replace(".", "[.]")
            
            # 2. BONUS SOC PRO-TIP: Ganti http/https menjadi hxxp/hxxps
            defanged_output = defanged_output.replace("http://", "hxxp://").replace("https://", "hxxps://")
            
            st.success("Berhasil!")
            st.text_area("📋 Hasil:", value=defanged_output, height=200)
        else:
            st.warning("⚠️ Masukkan teks IoC terlebih dahulu di kotak atas.")


# ==========================================
# TAB 4: BULK LOG PARSER & FORMATTER
# ==========================================
with tab4:
    st.subheader("📝 Bulk Log Parser & Plaintext Formatter")
    st.markdown("Ekstrak IP dari log mentah SOC, defang otomatis, dan format menjadi plaintext siap tempel.")
    
    raw_log_input = st.text_area(
        "Masukkan Raw Log / Data Mentah (Copy-Paste dari SIEM):", 
        height=300
    )
    
    def parse_and_format_logs(raw_text):
        lines = raw_text.strip().split('\n')
        results = []
        current_alert = "Unknown Alert"
        current_ips = set()
        
        # Regex untuk mendeteksi IPv4 yang valid
        ip_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Ekstrak IP jika ada di baris ini
            found_ips = ip_pattern.findall(line)
            
            if found_ips:
                for ip in found_ips:
                    current_ips.add(ip)
            else:
                # Jika tidak ada IP, cek apakah ini baris angka (jumlah alert) -> abaikan
                if line.isdigit():
                    continue
                
                # Abaikan baris metadata (URL, Hash, System, Account) yang bukan nama alert
                lower_line = line.lower()
                if any(lower_line.startswith(p) for p in ['url:', 'filehash:', 'system:', 'account:', 'host:', 'file:']):
                    continue
                    
                # Jika lolos semua filter di atas, asumsikan ini adalah 'Alert Name'
                # Simpan alert yang sedang diproses (jika sudah ada isinya) sebelum pindah ke alert baru
                if current_ips:
                    results.append({
                        "alert_name": current_alert,
                        "ips": list(current_ips)
                    })
                    current_ips = set() # Reset untuk alert baru
                
                current_alert = line
                
        # Simpan blok alert terakhir
        if current_ips:
            results.append({
                "alert_name": current_alert,
                "ips": list(current_ips)
            })
            
        return results

    if st.button("Parse & Generate Plaintext", type="primary"):
        if raw_log_input.strip():
            with st.spinner("Mengekstrak data dan merapikan format..."):
                parsed_data = parse_and_format_logs(raw_log_input)
                
                if not parsed_data:
                    st.warning("⚠️ Tidak ada IP yang berhasil diekstrak.")
                else:
                    output_text = ""
                    for item in parsed_data:
                        # Proses Defang IP (titik jadi kurung siku)
                        defanged_ips = [ip.replace(".", "[.]") for ip in item['ips']]
                        
                        # Susun plaintext
                        output_text += f"Alert Name: {item['alert_name']}\n"
                        output_text += "Justification: \n" # Dikosongkan sesuai permintaan
                        output_text += "Indicators:\n"
                        
                        # Gabungkan IP dengan koma dan pindah baris
                        output_text += ",\n".join(defanged_ips) + "\n\n"
                        
                        # Pemisah antar alert
                        output_text += "=========================================\n\n"
                    
                    # Bersihkan enter dan sama dengan berlebih di ujung text
                    output_text = output_text.strip().rstrip("=").strip()

                    st.success(f"Berhasil mengekstrak {len(parsed_data)} Alert!")
                    st.text_area(
                        "📋 Plaintext Output (Siap Copy-Paste tanpa gap 2 enter):", 
                        value=output_text, 
                        height=500
                    )
                    
                    # Fitur Download File TXT
                    st.download_button(
                        label="⬇️ Download sebagai .txt",
                        data=output_text,
                        file_name=f"Parsed_Indicators_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                        mime="text/plain"
                    )
        else:
            st.error("⚠️ Masukkan teks log mentah terlebih dahulu di kotak atas.")