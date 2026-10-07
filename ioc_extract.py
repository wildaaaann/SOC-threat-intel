"""Ekstraksi IoC (IP, domain, hash) dari teks alert.

Modul ini murni: tanpa Streamlit dan tanpa request jaringan, supaya bisa diuji
(`python3 -m unittest`) dan dipakai untuk mengukur akurasi ekstraksi.
"""

import ipaddress
import re
from urllib.parse import urlparse

# Ekstensi file yang sering terbaca sebagai TLD domain ("payload.exe", "app.py").
_FILE_EXTENSIONS = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "lnk", "msi", "jar", "bin", "so", "tmp", "dat",
    "txt", "log", "ini", "cfg", "conf", "config", "properties", "json", "xml", "yml", "yaml", "csv",
    "py", "js", "sh", "php", "asp", "aspx", "jsp", "class", "java", "html", "htm", "css",
    "zip", "rar", "gz", "tar", "7z", "iso", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf",
    "png", "jpg", "jpeg", "gif", "svg", "ico", "mp3", "mp4",
}

_HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}

_HASH_RE = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9a-fA-F])")
_IPV4_RE = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\d|\.\d)")
_URL_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s\"'<>]+")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,24})")
_DOMAIN_RE = re.compile(r"(?<![\w.\-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}(?![\w\-])")


def refang(text):
    """Kembalikan IoC yang di-defang ("evil[.]com", "hxxp") ke bentuk normal."""
    for token in ("[.]", "(.)", "{.}", "[dot]", "(dot)"):
        text = text.replace(token, ".")
    text = text.replace("[://]", "://").replace("[:]", ":").replace("[@]", "@")
    return re.sub(r"hxxp", "http", text, flags=re.IGNORECASE)


def _is_public_ip(value):
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _valid_domain(value):
    value = value.lower().rstrip(".")
    tld = value.rsplit(".", 1)[-1]
    return tld not in _FILE_EXTENSIONS and not re.fullmatch(r"[\d.]+", value)


def extract_iocs(text):
    """Ambil IoC unik dari teks alert.

    Mengembalikan list of dict: {"value", "type", "public"} dengan type salah satu
    dari ip, domain, md5, sha1, sha256. Urutan mengikuti kemunculan pertama per tipe.
    """
    if not text or not text.strip():
        return []

    text = refang(text)
    found = {"hash": [], "domain": [], "ip": []}

    def add(kind, value):
        if value not in found[kind]:
            found[kind].append(value)

    # 1) URL: ambil host-nya, lalu buang URL dari teks agar path ("/index.php") tidak terbaca sebagai domain.
    for url in _URL_RE.findall(text):
        host = (urlparse(url).hostname or "").lower()
        if _IPV4_RE.fullmatch(host):
            add("ip", host)
        elif host and "." in host and _valid_domain(host):
            add("domain", host.rstrip("."))
    text = _URL_RE.sub(" ", text)

    # 2) Email: ambil domainnya, buang alamatnya ("john.doe@corp.com" tidak boleh menghasilkan "john.doe").
    for domain in _EMAIL_RE.findall(text):
        if _valid_domain(domain):
            add("domain", domain.lower().rstrip("."))
    text = _EMAIL_RE.sub(" ", text)

    # 3) Hash, IP, lalu domain dari sisa teks.
    for value in _HASH_RE.findall(text):
        add("hash", value.lower())
    text = _HASH_RE.sub(" ", text)

    for value in _IPV4_RE.findall(text):
        add("ip", value)
    text = _IPV4_RE.sub(" ", text)

    for value in _DOMAIN_RE.findall(text):
        if _valid_domain(value):
            add("domain", value.lower().rstrip("."))

    result = []
    for value in found["hash"]:
        result.append({"value": value, "type": _HASH_TYPES[len(value)], "public": True})
    for value in found["domain"]:
        result.append({"value": value, "type": "domain", "public": True})
    for value in found["ip"]:
        result.append({"value": value, "type": "ip", "public": _is_public_ip(value)})
    return result


_PRIMARY_PRIORITY = ["sha256", "sha1", "md5", "domain", "ip"]


def pick_primary(iocs):
    """Pilih IoC utama: hash dulu, lalu domain, lalu IP publik. IP privat tidak dipilih."""
    for kind in _PRIMARY_PRIORITY:
        for item in iocs:
            if item["type"] == kind and item["public"]:
                return item["value"]
    return None


def first_public_ip(iocs):
    """IP publik pertama, untuk mengisi Related IP AbuseIPDB."""
    for item in iocs:
        if item["type"] == "ip" and item["public"]:
            return item["value"]
    return None
