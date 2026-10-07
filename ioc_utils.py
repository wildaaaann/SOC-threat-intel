"""Fungsi murni (tanpa Streamlit) untuk ekstraksi IoC, status hasil CTI, dan pembacaan verdict AI.

Dipisah dari app.py supaya bisa diuji dengan pytest tanpa membuka UI.
"""

import ipaddress
import json
import re

VERDICTS = ("True Positive", "False Positive", "Likely Benign")

# Urutan saran Primary IoC: hash lebih spesifik daripada domain, domain lebih spesifik daripada IP.
_PRIORITY = ("sha256", "sha1", "md5", "domain", "ip")

_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IPV4 = re.compile(rf"(?<![\w.]){_OCTET}(?:\.{_OCTET}){{3}}(?!\w|\.\w)")
_HASH = re.compile(r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})(?![A-Fa-f0-9])")
_DOMAIN = re.compile(
    r"(?<![\w.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?![\w@-])",
    re.IGNORECASE,
)

# Ekstensi berkas yang hampir selalu nama file di log, bukan domain.
# Ekstensi yang juga TLD sungguhan dan sering disalahgunakan (.zip, .mov, .sh, .py) sengaja tidak dimasukkan:
# lebih baik analis menyaring satu kandidat berlebih daripada kehilangan IoC.
_FILE_EXTENSIONS = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "jar", "msi", "lnk", "tmp", "log", "txt", "csv",
    "json", "xml", "yaml", "yml", "ini", "conf", "cfg", "dat", "bin", "gz", "tar", "doc", "docx", "xls",
    "xlsx", "ppt", "pptx", "pdf", "png", "jpg", "jpeg", "gif", "svg", "css", "rtf", "iso", "img", "scr",
    "hta", "wsf", "dmp", "evtx", "pcap", "php", "asp", "aspx", "jsp", "html", "htm", "class",
}

# Nama kolom akar pada alert Wazuh (rule.id, agent.id, data.srcip) yang kebetulan berbentuk domain.
_LOG_FIELD_ROOTS = {
    "rule", "agent", "data", "win", "system", "eventdata", "manager", "decoder", "predecoder",
    "location", "syscheck", "audit", "full_log", "srcip", "dstip", "timestamp",
}


def _refang(text: str) -> str:
    """Kembalikan IoC yang di-defang ([.], hxxp) ke bentuk biasa agar bisa dikenali."""
    text = re.sub(r"\[\.\]|\(\.\)|\{\.\}", ".", text)
    text = re.sub(r"\[:\]", ":", text)
    return re.sub(r"hxxp", "http", text, flags=re.IGNORECASE)


def _unique(items):
    seen, out = set(), []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def extract_iocs(text: str) -> dict:
    """Ambil IP publik, domain, dan hash dari teks alert.

    IP non-publik (private, loopback, link-local, reserved) tidak dimasukkan ke `ip`,
    tetapi dicatat di `skipped_ip` supaya analis tahu IP itu ada dan sengaja tidak dikirim ke layanan CTI.
    """
    text = _refang(text or "")
    found = {"ip": [], "domain": [], "md5": [], "sha1": [], "sha256": [], "skipped_ip": []}

    for value in _unique(_IPV4.findall(text)):
        key = "ip" if ipaddress.ip_address(value).is_global else "skipped_ip"
        found[key].append(value)

    for value in _unique(h.lower() for h in _HASH.findall(text)):
        found[{32: "md5", 40: "sha1", 64: "sha256"}[len(value)]].append(value)

    domains = []
    for match in _DOMAIN.findall(text):
        domain = match.lower()
        labels = domain.split(".")
        if labels[-1] in _FILE_EXTENSIONS or labels[0] in _LOG_FIELD_ROOTS or len(domain) > 253:
            continue
        domains.append(domain)
    found["domain"] = _unique(domains)
    return found


def ioc_options(found: dict) -> list:
    """Daftar (tipe, nilai) berurutan dari yang paling spesifik."""
    return [(kind, value) for kind in _PRIORITY for value in found.get(kind, [])]


def suggest_primary(found: dict) -> tuple:
    """Saran (primary_ioc, related_ip). Related IP dipakai AbuseIPDB saat primary bukan IP."""
    options = ioc_options(found)
    if not options:
        return "", ""
    kind, value = options[0]
    related = "" if kind == "ip" else (found["ip"][0] if found.get("ip") else "")
    return value, related


def classify_source_result(result) -> tuple:
    """Ubah keluaran query CTI menjadi (status, keterangan) untuk panel bukti.

    Status: OK, Gagal, Sebagian gagal, Tidak ada data, Tidak dikueri, Tidak diketahui.
    """
    if result is None or result == "":
        return "Tidak dikueri", ""

    if isinstance(result, dict):  # hasil relationships VirusTotal: {endpoint: data atau {"error": ...}}
        if not result:
            return "Tidak dikueri", ""
        errors = {k: v["error"] for k, v in result.items() if isinstance(v, dict) and "error" in v}
        detail = "; ".join(f"{k}: {msg}" for k, msg in errors.items())[:200]
        if errors and len(errors) == len(result):
            return "Gagal", detail
        if errors:
            return "Sebagian gagal", detail
        return "OK", ""

    try:
        data = json.loads(result)
    except (TypeError, ValueError):
        return "Tidak diketahui", ""

    if isinstance(data, dict):
        if "error" in data:
            return "Gagal", str(data["error"])[:200]
        if not data:
            return "Tidak ada data", ""
        if set(data) == {"message"}:
            return "Tidak ada data", str(data["message"])[:200]
    return "OK", ""


_VERDICT_LINE = re.compile(r"^[ \t]*AI_VERDICT:[ \t]*(.+?)[ \t]*$", re.MULTILINE | re.IGNORECASE)


def parse_ai_verdict(text: str) -> tuple:
    """Pisahkan baris `AI_VERDICT: ...` dari laporan.

    Mengembalikan (verdict atau None, teks laporan tanpa baris itu).
    Verdict hanya diterima jika sama persis (tanpa memperhatikan huruf besar) dengan salah satu VERDICTS.
    """
    matches = list(_VERDICT_LINE.finditer(text or ""))
    if not matches:
        return None, text

    raw = matches[-1].group(1).strip().strip("`*_. ")
    verdict = next((v for v in VERDICTS if v.lower() == raw.lower()), None)

    def _drop(match):
        # Jika pagar kode penutup menempel di baris yang sama, pertahankan pagarnya.
        return "```" if match.group(0).rstrip().endswith("```") else ""

    cleaned = _VERDICT_LINE.sub(_drop, text)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).rstrip() + "\n"
    return verdict, cleaned
