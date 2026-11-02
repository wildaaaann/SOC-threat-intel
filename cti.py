"""Pengayaan CTI: query ke sumber luar, ringkasan hasil, dan log pengambilan.

Modul ini murni (tanpa Streamlit) supaya dipakai bersama oleh app.py dan worker.py. Verifikasi TLS selalu
diberikan lewat parameter `verify`; tidak ada default yang mematikannya.
Throttle dan cache opsional: app interaktif tidak memakainya, worker otomatis memakainya agar kuota gratis awet.
"""

import json
import os
import re
import tempfile
import time
from datetime import datetime, timezone

import requests

# --- Throttle per sumber (detik minimal antar request). Kosong = tanpa batas. ---
_MIN_INTERVAL = {}
_LAST_CALL = {}


def set_min_interval(source, seconds):
    """Mis. set_min_interval('virustotal', 16) untuk batas gratis sekitar 4 request per menit."""
    _MIN_INTERVAL[source] = float(seconds)


def _wait(source):
    interval = _MIN_INTERVAL.get(source, 0)
    if interval > 0:
        remaining = interval - (time.monotonic() - _LAST_CALL.get(source, -1e9))
        if remaining > 0:
            time.sleep(remaining)
    _LAST_CALL[source] = time.monotonic()


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


def query_virustotal(ioc, ioc_type, api_key, verify=True):
    if not api_key: return '{"error": "VirusTotal API key not configured."}'
    if ioc_type == "ip": url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc_type in ["md5", "sha1", "sha256"]: url = f"https://www.virustotal.com/api/v3/files/{ioc}"
    elif ioc_type == "domain": url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
    else: return '{"error": "Unsupported IoC type."}'
    try:
        _wait("virustotal")
        response = requests.get(url, headers={"x-apikey": api_key}, timeout=15, verify=verify)
        response.raise_for_status()
        return json.dumps(response.json().get("data", {}).get("attributes", {}), indent=2)
    except Exception as e: return f'{{"error": "{str(e)}"}}'


def query_virustotal_relationships(ioc, ioc_type, api_key, verify=True):
    if not api_key: return {}
    base_urls = {"ip": f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}/", "domain": f"https://www.virustotal.com/api/v3/domains/{ioc}/", "file": f"https://www.virustotal.com/api/v3/files/{ioc}/"}
    endpoints_map = {"ip": ["resolutions", "communicating_files"], "domain": ["resolutions", "communicating_files"], "file": ["contacted_domains", "contacted_ips", "execution_parents"]}
    ioc_key = "file" if ioc_type in ["md5", "sha1", "sha256"] else ioc_type
    if ioc_key not in base_urls: return {}
    relationship_data = {}
    for endpoint in endpoints_map[ioc_key]:
        try:
            _wait("virustotal")
            response = requests.get(base_urls[ioc_key] + endpoint, headers={"x-apikey": api_key}, params={'limit': 10}, timeout=15, verify=verify)
            response.raise_for_status()
            relationship_data[endpoint] = response.json().get("data", [])
        except Exception as e: relationship_data[endpoint] = {"error": str(e)}
    return relationship_data


def query_abuseipdb(ip, api_key, verify=True):
    if not ip: return ""
    if not api_key: return '{"error": "AbuseIPDB API key not configured."}'
    try:
        _wait("abuseipdb")
        response = requests.get("https://api.abuseipdb.com/api/v2/check", headers={"Accept": "application/json", "Key": api_key}, params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""}, timeout=15, verify=verify)
        response.raise_for_status()
        return json.dumps(response.json().get("data", {}), indent=2)
    except Exception as e: return f'{{"error": "{str(e)}"}}'


def query_tip_neiki(ioc, ioc_type, verify=True):
    if ioc_type not in ["md5", "sha1", "sha256"]: return ""
    try:
        response = requests.get(f"https://tip.neiki.dev/api/reports/file/{ioc}", timeout=30, verify=verify)
        response.raise_for_status()
        return json.dumps(response.json(), indent=2)
    except Exception as e: return f'{{"error": "{str(e)}"}}'


def query_urlscan(ioc, ioc_type, api_key, verify=True):
    if not api_key: return '{"error": "URLScan API key not configured."}'
    if ioc_type not in ['domain', 'ip']: return ""
    try:
        headers = {'API-Key': api_key, 'Content-Type': 'application/json'}
        query_val = f"domain:{ioc}" if ioc_type == "domain" else f"ip:{ioc}"
        _wait("urlscan")
        response = requests.get(f"https://urlscan.io/api/v1/search/?q={query_val}", headers=headers, timeout=15, verify=verify)
        response.raise_for_status()
        results = response.json().get('results', [])
        if results:
            top_result = results[0]
            summary = {"latest_scan_url": top_result.get('result'), "verdicts": top_result.get('verdicts', {}), "task_time": top_result.get('task', {}).get('time')}
            return json.dumps(summary, indent=2)
        return '{"message": "No previous scans found on URLScan."}'
    except Exception as e: return f'{{"error": "{str(e)}"}}'


def query_hybridanalysis(ioc, ioc_type, api_key, verify=True):
    if not api_key: return '{"error": "HybridAnalysis API key not configured."}'
    if ioc_type not in ["md5", "sha1", "sha256"]: return ""
    try:
        headers = {
            'api-key': api_key,
            'User-Agent': 'Falcon Sandbox',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        _wait("hybridanalysis")
        response = requests.post("https://hybrid-analysis.com/api/v2/search/hash", headers=headers, data={'hash': ioc}, timeout=15, verify=verify)
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


def utc_stamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


class CtiCache:
    """Cache hasil CTI per (sumber, nilai) dengan masa berlaku. Hanya hasil sukses yang disimpan.

    Waktu pengambilan asli ikut tersimpan, jadi log tetap jujur tentang seberapa tua datanya.
    """

    def __init__(self, path=None, ttl_s=86400):
        self.path = path
        self.ttl_s = ttl_s
        self._data = {}
        if path and os.path.exists(path):
            try:
                with open(path, encoding="utf8") as handle:
                    self._data = json.load(handle)
            except (OSError, ValueError):
                self._data = {}

    @staticmethod
    def _key(source, queried):
        return f"{source}|{queried}"

    def get(self, source, queried):
        entry = self._data.get(self._key(source, queried))
        if not entry:
            return None
        try:
            age = (datetime.now(timezone.utc) - datetime.strptime(entry["at"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)).total_seconds()
        except (KeyError, ValueError):
            return None
        return (entry["at"], entry["result"]) if age <= self.ttl_s else None

    def put(self, source, queried, retrieved_at, result):
        self._data[self._key(source, queried)] = {"at": retrieved_at, "result": result}
        if self.path:
            folder = os.path.dirname(self.path)
            if folder:
                os.makedirs(folder, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=folder or ".", suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf8") as handle:
                json.dump(self._data, handle)
            os.replace(tmp, self.path)


def run_cti(log, source, queried, applicable, fn, *args, cache=None):
    """Jalankan satu query CTI dan catat sumber, nilai yang di-query, waktu UTC, status, dan temuan utama."""
    if not applicable:
        log.append({"Sumber": source, "Query": queried, "Waktu (UTC)": "n/a", "Status": "Dilewati", "Temuan": "Tidak berlaku untuk tipe IoC ini"})
        return ""
    cached = cache.get(source, queried) if cache else None
    if cached:
        retrieved_at, result = cached
        status, finding = summarize_cti(source, result)
        log.append({"Sumber": source, "Query": queried, "Waktu (UTC)": retrieved_at, "Status": status, "Temuan": f"{finding} [dari cache]"})
        return result
    result = fn(*args)
    status, finding = summarize_cti(source, result)
    retrieved_at = utc_stamp()
    log.append({"Sumber": source, "Query": queried, "Waktu (UTC)": retrieved_at, "Status": status, "Temuan": finding})
    if cache and status in ("OK", "Tidak ada data"):
        cache.put(source, queried, retrieved_at, result)
    return result
