"""Set skenario uji dengan kunci jawaban, dan daftar pilihan keputusan respons.

Skenario disimpan di scenarios/scenarios.json (bisa diganti dengan berkas unggahan). Kunci jawaban
(`ground_truth`) tidak boleh tampil di layar analis sebelum keputusannya tercatat.
Modul ini murni (tanpa Streamlit).
"""

import json

from triage_report import VERDICTS

# Pilihan "keputusan respons pertama". Daftar ini draf: sesuaikan setelah definisi disepakati dengan dosen/mentor.
RESPONSE_ACTIONS = (
    "Tutup sebagai False Positive",
    "Pantau / tunggu data tambahan",
    "Blokir indikator di kontrol keamanan",
    "Isolasi perangkat",
    "Eskalasi ke tim lain / L2",
    "Reset kredensial / batasi akses",
)

_REQUIRED_TEXT = ("id", "title", "alert_name", "alert_text", "primary_ioc")


def validate_scenarios(data):
    """Periksa daftar skenario. Mengembalikan (skenario_valid, daftar_pesan_kesalahan)."""
    errors = []
    if not isinstance(data, list):
        return [], ["Berkas skenario harus berupa array JSON"]

    valid, seen = [], set()
    for position, item in enumerate(data, start=1):
        label = f"Skenario #{position}"
        if not isinstance(item, dict):
            errors.append(f"{label}: bukan objek")
            continue
        label = f"Skenario '{item.get('id', position)}'"
        missing = [f for f in _REQUIRED_TEXT if not isinstance(item.get(f), str) or not item[f].strip()]
        if missing:
            errors.append(f"{label}: kolom wajib kosong atau hilang: {', '.join(missing)}")
            continue
        if item["id"] in seen:
            errors.append(f"{label}: id ganda")
            continue
        truth = item.get("ground_truth")
        if not isinstance(truth, dict) or truth.get("verdict") not in VERDICTS:
            errors.append(f"{label}: ground_truth.verdict harus salah satu dari {', '.join(VERDICTS)}")
            continue
        actions = truth.get("correct_actions")
        if not isinstance(actions, list) or not actions or any(a not in RESPONSE_ACTIONS for a in actions):
            errors.append(f"{label}: ground_truth.correct_actions harus berisi minimal satu aksi dari daftar RESPONSE_ACTIONS")
            continue
        seen.add(item["id"])
        valid.append({
            "id": item["id"].strip(),
            "title": item["title"].strip(),
            "alert_name": item["alert_name"].strip(),
            "alert_text": item["alert_text"].strip(),
            "primary_ioc": item["primary_ioc"].strip(),
            "related_ip": str(item.get("related_ip", "") or "").strip(),
            "action_taken": str(item.get("action_taken", "") or "").strip(),
            "ground_truth": {
                "verdict": truth["verdict"],
                "correct_actions": list(actions),
                "key_evidence": str(truth.get("key_evidence", "") or ""),
            },
            "synthetic": bool(item.get("synthetic", False)),
            "validated": bool(item.get("validated", False)),
        })
    return valid, errors


def parse_scenarios(text):
    try:
        data = json.loads(text)
    except ValueError as exc:
        return [], [f"JSON tidak valid: {exc}"]
    return validate_scenarios(data)


def load_scenarios(path):
    try:
        with open(path, encoding="utf8") as handle:
            return parse_scenarios(handle.read())
    except OSError as exc:
        return [], [f"Tidak bisa membuka {path}: {exc}"]
