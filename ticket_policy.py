"""Aturan penutupan tiket otomatis, penilaian review manusia, dan ringkasan Mode Otomatis.

Modul ini murni (tanpa Streamlit). Prinsip: AI hanya menutup tiket bila hasilnya lengkap dan konsisten.
Selain itu tiket tetap terbuka dengan status "Perlu manusia", karena menutup tiket dari laporan yang rusak
atau data CTI yang gagal sama dengan membuang alert tanpa dilihat siapa pun.
"""

import statistics
from datetime import datetime, timezone

from triage_report import SEVERITIES, UNREADABLE, VERDICTS, parse_closing_reason, parse_description, parse_recommendations, parse_severity, parse_ai_verdict
from wazuh_client import parse_timestamp

STATUS_CLOSED_AI = "Closed by AI"
STATUS_NEEDS_HUMAN = "Perlu manusia"
STATUS_CLOSED_HUMAN = "Closed by analis"

REVIEW_PENDING = "Belum direview"
REVIEW_CONFIRMED = "Dikonfirmasi"
REVIEW_CORRECTED = "Dikoreksi"

PRIORITY_MUST = "Wajib (prioritas tinggi)"
PRIORITY_NORMAL = "Biasa"
PRIORITY_HUMAN = "Tindakan manusia"

_BENIGN = ("False Positive", "Likely Benign")


def decide(ctx, gen):
    """Kembalikan (status, daftar_alasan_tahan, prioritas_review, hasil_parse) untuk satu alert.

    `ctx` hasil triage_pipeline.enrich (atau {"error": ...}); `gen` hasil generate_report (atau None bila enrich gagal).
    """
    parsed = {"verdict": UNREADABLE, "severity": UNREADABLE, "closing_reason": "", "description": "", "recommendations": ""}
    holds = []

    if "error" in ctx:
        error = str(ctx["error"])
        if "wajib diisi" in error:
            # Pesan pipeline ditulis untuk form manual; reviewer tiket perlu kalimat yang menjelaskan alert-nya.
            error = "Tidak ada IoC publik (IP, domain, hash) pada alert ini untuk diperkaya"
        return STATUS_NEEDS_HUMAN, [f"Tidak bisa diperkaya: {error}"], PRIORITY_HUMAN, parsed

    report = gen["report"]
    parsed = {
        "verdict": parse_ai_verdict(report), "severity": parse_severity(report),
        "closing_reason": parse_closing_reason(report), "description": parse_description(report),
        "recommendations": parse_recommendations(report),
    }

    statuses = {row["Sumber"]: row["Status"] for row in ctx["cti_log"]}
    if statuses.get("VirusTotal") == "Gagal":
        holds.append("VirusTotal gagal (kuota habis atau jaringan)")
    elif not any(s == "OK" for s in statuses.values()):
        holds.append("Tidak ada sumber CTI yang berhasil")

    if gen["llm_used"]["provider"] == "-":
        holds.append("Semua penyedia AI gagal")
    else:
        missing = [name for name, ok in gen["layers"].items() if not ok]
        if missing:
            holds.append(f"Laporan AI tidak memuat lapisan: {', '.join(missing)}")
        if parsed["verdict"] == UNREADABLE:
            holds.append("Verdict AI tidak terbaca")
        if parsed["severity"] == UNREADABLE:
            holds.append("Severity AI tidak terbaca")
        if not parsed["closing_reason"]:
            holds.append("Alasan penutupan AI kosong")
        if not parsed["recommendations"]:
            holds.append("Rekomendasi AI kosong")
        if not parsed["description"]:
            holds.append("Deskripsi AI kosong")
        # Verdict dan severity yang saling bertentangan menandakan AI salah paham; jangan ditutup.
        if (parsed["verdict"] in _BENIGN and parsed["severity"] in ("High", "Critical")) or \
           (parsed["verdict"] == "True Positive" and parsed["severity"] == "Low"):
            holds.append(f"Verdict ({parsed['verdict']}) dan severity ({parsed['severity']}) tidak konsisten")

    if holds:
        return STATUS_NEEDS_HUMAN, holds, PRIORITY_HUMAN, parsed
    must = parsed["verdict"] == "True Positive" or parsed["severity"] in ("High", "Critical")
    return STATUS_CLOSED_AI, [], (PRIORITY_MUST if must else PRIORITY_NORMAL), parsed


def build_ticket(alert, entities, ctx, gen, *, tls_verify, processing_s):
    """Susun satu tiket dari hasil pemrosesan. `gen` None bila pengayaan gagal sebelum AI dipanggil."""
    status, holds, priority, parsed = decide(ctx, gen)
    now = datetime.now(timezone.utc)
    alert_ts = parse_timestamp(alert.get("timestamp"))
    ok = "error" not in ctx
    ticket = {
        "id": alert["id"],
        "alert_timestamp": alert.get("timestamp", ""),
        "rule_id": alert.get("rule_id", ""),
        "rule_description": alert.get("rule_description", ""),
        "rule_level": alert.get("rule_level"),
        "agent_name": alert.get("agent_name", ""),
        "agent_ip": alert.get("agent_ip", ""),
        "entities": entities,
        "ioc": ctx.get("ioc", "") if ok else "",
        "ioc_type": ctx.get("ioc_type", "") if ok else "",
        "cti_log": ctx.get("cti_log", []) if ok else [],
        "ai_verdict": parsed["verdict"],
        "severity": parsed["severity"],
        "closing_reason": parsed["closing_reason"],
        "description": parsed["description"],
        "recommendations": parsed["recommendations"],
        "report": gen["report"] if gen else "",
        "prompt": ctx.get("final_prompt", "") if ok else "",
        "layers_ok": gen["layers_ok"] if gen else False,
        "llm_provider": gen["llm_used"]["provider"] if gen else None,
        "llm_model": gen["llm_used"]["model"] if gen else None,
        "llm_fallback_used": gen["llm_fallback_used"] if gen else None,
        "tls_verify": tls_verify,
        "status": status,
        "hold_reasons": holds,
        "review_priority": priority,
        "review_status": REVIEW_PENDING,
        "processed_at_utc": now.strftime("%Y-%m-%d %H:%M:%S"),
        "processing_s": round(processing_s, 2),
        "alert_to_close_s": round((now - alert_ts).total_seconds(), 1) if (alert_ts and status == STATUS_CLOSED_AI) else None,
    }
    return ticket


def review_changes(ticket, *, reviewer, final_severity, reason_ok=None, corrected_reason="", final_verdict=None, note="",
                   manual_description="", manual_recommendations=""):
    """Ubah hasil review manusia menjadi field update. ValueError (pesan Indonesia) bila isiannya belum lengkap.

    Kolom Manual: `final_severity`, `final_reason`, `final_description`, `final_recommendations`. Deskripsi dan
    rekomendasi yang dikosongkan berarti reviewer menerima teks AI, dan disalin apa adanya supaya kolom Manual
    selalu berisi nilai akhir yang dipakai. Pada tiket "Perlu manusia" teks AI itu bisa kosong, jadi tetap kosong.

    Tiket "Closed by AI": reviewer memastikan severity dan alasan. Tiket "Perlu manusia": analis menentukan
    verdict, severity, dan alasan penutupan sendiri.
    """
    if not (reviewer or "").strip():
        raise ValueError("Kode reviewer wajib diisi.")
    if final_severity not in SEVERITIES:
        raise ValueError("Pilih severity akhir.")
    now = datetime.now(timezone.utc)
    base = {"reviewer": reviewer.strip(), "reviewed_at_utc": now.strftime("%Y-%m-%d %H:%M:%S"), "final_severity": final_severity, "review_note": (note or "").strip()}
    created = datetime.strptime(ticket["processed_at_utc"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    base["review_after_s"] = round((now - created).total_seconds(), 1)
    base["final_description"] = (manual_description or "").strip() or ticket.get("description", "")
    base["final_recommendations"] = (manual_recommendations or "").strip() or ticket.get("recommendations", "")
    base["description_agree"] = (not (manual_description or "").strip()) if ticket.get("description") else None
    base["recommendations_agree"] = (not (manual_recommendations or "").strip()) if ticket.get("recommendations") else None

    if ticket["status"] == STATUS_NEEDS_HUMAN:
        if final_verdict not in VERDICTS:
            raise ValueError("Pilih verdict akhir.")
        if not (corrected_reason or "").strip():
            raise ValueError("Tulis alasan penutupan.")
        base.update({"status": STATUS_CLOSED_HUMAN, "review_status": REVIEW_CORRECTED, "final_verdict": final_verdict,
                     "final_reason": corrected_reason.strip(), "severity_agree": None, "reason_agree": None})
        return base

    if reason_ok is None:
        raise ValueError("Tentukan apakah alasan penutupan sudah benar.")
    if not reason_ok and not (corrected_reason or "").strip():
        raise ValueError("Tulis alasan penutupan yang benar.")
    severity_agree = final_severity == ticket["severity"]
    base.update({
        "severity_agree": severity_agree, "reason_agree": bool(reason_ok),
        "final_reason": ticket["closing_reason"] if reason_ok else corrected_reason.strip(),
        "review_status": REVIEW_CONFIRMED if (severity_agree and reason_ok) else REVIEW_CORRECTED,
    })
    return base


def _percent(values):
    known = [v for v in values if v is not None]
    return 100.0 * sum(1 for v in known if v) / len(known) if known else None


def summarize_tickets(tickets):
    """Angka ringkas Mode Otomatis, termasuk seberapa sering manusia setuju dengan AI."""
    closed = [t for t in tickets if t.get("status") == STATUS_CLOSED_AI]
    reviewed = [t for t in closed if t.get("review_status") != REVIEW_PENDING]
    times = [t["alert_to_close_s"] for t in closed if isinstance(t.get("alert_to_close_s"), (int, float))]
    return {
        "Tiket total": len(tickets),
        "Closed by AI": len(closed),
        "Perlu manusia (tidak ditutup)": sum(1 for t in tickets if t.get("status") == STATUS_NEEDS_HUMAN),
        "Closed by analis": sum(1 for t in tickets if t.get("status") == STATUS_CLOSED_HUMAN),
        "Closed by AI belum direview": len(closed) - len(reviewed),
        "True Positive yang ditutup AI": sum(1 for t in closed if t.get("ai_verdict") == "True Positive"),
        "Sudah direview": len(reviewed),
        "Severity disetujui (%)": _percent([t.get("severity_agree") for t in reviewed]),
        "Alasan disetujui (%)": _percent([t.get("reason_agree") for t in reviewed]),
        "Alert ke tutup, median (detik)": statistics.median(times) if times else None,
    }


def sort_for_review(tickets):
    """Urutan antrean: belum direview di atas; di dalamnya tindakan manusia, wajib review, lalu biasa; terbaru dulu."""
    rank = {PRIORITY_HUMAN: 0, PRIORITY_MUST: 1, PRIORITY_NORMAL: 2}
    newest_first = sorted(tickets, key=lambda t: t.get("processed_at_utc", ""), reverse=True)
    return sorted(newest_first, key=lambda t: (t.get("review_status") != REVIEW_PENDING, rank.get(t.get("review_priority"), 3)))
