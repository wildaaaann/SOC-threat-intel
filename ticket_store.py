"""Penyimpanan tiket Mode Otomatis dan status worker.

Tiket memakai penyimpanan append-only yang sama dengan trial evaluasi (trial_store.TrialStore): id tiket = id alert
Wazuh, sehingga alert yang sama tidak pernah menjadi dua tiket. Review manusia ditulis sebagai baris `_update`.
Modul ini murni (tanpa Streamlit).
"""

import csv
import io
import json
import os
import tempfile

from trial_store import TrialStore, utc_now_iso


class TicketStore(TrialStore):
    def known_ids(self):
        return {t["id"] for t in self.all()}


def read_worker_state(path):
    """Status terakhir worker (kursor, detak jantung, galat). {} bila belum ada atau rusak."""
    try:
        with open(path, encoding="utf8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def write_worker_state(path, state):
    """Tulis atomik agar UI tidak pernah membaca berkas setengah jadi."""
    folder = os.path.dirname(path) or "."
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=folder, suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf8") as handle:
        json.dump(state, handle)
    os.replace(tmp, path)


TICKET_CSV_FIELDS = [
    "id", "alert_timestamp", "rule_id", "rule_description", "rule_level", "agent_name", "ioc", "ioc_type", "status",
    "ai_verdict", "severity", "closing_reason", "description", "recommendations", "review_priority", "review_status", "reviewer", "reviewed_at_utc",
    "final_severity", "severity_agree", "reason_agree", "final_verdict", "final_reason", "final_description", "final_recommendations", "description_agree", "recommendations_agree", "review_note", "entities",
    "alert_to_close_s", "review_after_s", "processing_s", "llm_provider", "llm_model", "llm_fallback_used", "tls_verify", "hold_reasons",
]


def tickets_to_csv(tickets):
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=TICKET_CSV_FIELDS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for ticket in tickets:
        row = {}
        for field in TICKET_CSV_FIELDS:
            value = ticket.get(field)
            if field == "entities":
                value = [f"{e.get('field', '')}={e.get('value', '')}" for e in (value or [])]
            row[field] = "; ".join(value) if isinstance(value, list) else ("" if value is None else value)
        writer.writerow(row)
    return buffer.getvalue()


__all__ = ["TicketStore", "read_worker_state", "write_worker_state", "tickets_to_csv", "TICKET_CSV_FIELDS", "utc_now_iso"]
