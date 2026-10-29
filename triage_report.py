"""Membaca laporan triage AI: verdict pada baris Conclusion dan tiga lapisan (fakta, pengayaan, inferensi).

Modul ini murni (tanpa Streamlit) supaya bisa diuji dan dipakai untuk evaluasi.
Templat laporan ada di app.py (SOC_ANALYST_ROLE). Jika judul lapisan atau baris Conclusion di sana
diubah, ubah juga konstanta di file ini dan jalankan tests/test_triage_report.py.
"""

import re

VERDICTS = ("True Positive", "False Positive", "Likely Benign")
UNREADABLE = "Tidak terbaca"

LAYER_KEYS = {"1": "fakta", "2": "pengayaan", "3": "inferensi"}

_CANON = {v.lower(): v for v in VERDICTS}

# "Conclusion: True Positive", "**Conclusion:** False Positive", "Conclusion - Likely Benign".
# Verdict yang diikuti "|" ditolak: itu sisa templat ("[True Positive|False Positive|Likely Benign]").
_CONCLUSION = re.compile(
    r"conclusion[\s*_`]*[:\-–—][\s*_`\"'\[(]*(true positive|false positive|likely benign)(?![A-Za-z])(?!\s*\|)",
    re.IGNORECASE,
)

# Judul bagian bernomor, mis. "3. LAYER 1 - ALERT FACTS" atau "5. RECOMMENDATIONS".
_HEADING = re.compile(r"^[ \t]*[*#_`]*\s*(\d+)\s*[.)]\s*(.+?)[ \t]*$", re.MULTILINE)
_LAYER_TITLE = re.compile(r"^[*_`\s]*LAYER\s*([123])\b", re.IGNORECASE)


def parse_ai_verdict(report_text):
    """Verdict dari baris Conclusion, atau 'Tidak terbaca' bila formatnya tidak ditemukan."""
    for match in _CONCLUSION.finditer(report_text or ""):
        return _CANON[match.group(1).lower()]
    return UNREADABLE


def parse_layers(report_text):
    """Pisahkan isi tiap lapisan. Mengembalikan {"fakta": teks|None, "pengayaan": ..., "inferensi": ...}."""
    text = report_text or ""
    headings = list(_HEADING.finditer(text))
    layers = {name: None for name in LAYER_KEYS.values()}
    for index, heading in enumerate(headings):
        layer = _LAYER_TITLE.match(heading.group(2))
        if not layer:
            continue
        end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        layers[LAYER_KEYS[layer.group(1)]] = text[heading.end():end].strip()
    return layers


def layers_complete(report_text):
    """True bila ketiga lapisan ada dan masing-masing berisi teks."""
    return all(layers_status(report_text).values())


def layers_status(report_text):
    """{"fakta": bool, "pengayaan": bool, "inferensi": bool}: lapisan ada dan tidak kosong."""
    return {name: bool(body) for name, body in parse_layers(report_text).items()}
