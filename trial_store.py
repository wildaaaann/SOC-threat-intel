"""Penyimpanan trial evaluasi (satu baris JSON per kejadian, hanya ditambah di akhir berkas).

Mengapa begini: riwayat di `st.session_state` hilang saat halaman di-refresh, dan beberapa analis bisa memakai
aplikasi bersamaan. Berkas append-only tidak saling menimpa. Penilaian rubrik ditulis sebagai baris `_update`
dan digabung saat dibaca. Pada hosting dengan disk sementara (mis. Streamlit Cloud) berkas ikut hilang saat
aplikasi restart: unduh JSONL secara berkala dan gunakan `import_text` untuk memulihkan.
Modul ini murni (tanpa Streamlit).
"""

import csv
import io
import json
import os
import uuid
from datetime import datetime, timezone

CSV_FIELDS = [
    "id", "recorded_at_utc", "participant", "condition", "source", "scenario_id", "alert_name", "ioc",
    "t_start_utc", "t_report_ready_utc", "t_decision_utc",
    "mttr_s", "system_latency_s", "analyst_time_s", "mttr_from_alert_s",
    "decision_verdict", "decision_action", "decision_note",
    "ground_truth_verdict", "correct_actions", "verdict_correct", "action_correct",
    "ai_verdict", "ai_correct", "report_layers_ok",
    "llm_provider", "llm_model", "llm_fallback_used", "analysis_mode", "tls_verify",
    "rubric_evidence", "rubric_recommendation", "rubric_rater", "rubric_note",
]


def utc_now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def new_trial_id():
    return uuid.uuid4().hex[:8]


class TrialStore:
    def __init__(self, path):
        self.path = path
        self.skipped_lines = 0

    def _read_lines(self):
        self.skipped_lines = 0
        try:
            with open(self.path, encoding="utf8") as handle:
                raw = handle.read().splitlines()
        except FileNotFoundError:
            return []
        rows = []
        for line in raw:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError:
                self.skipped_lines += 1
                continue
            if isinstance(row, dict):
                rows.append(row)
            else:
                self.skipped_lines += 1
        return rows

    def _write_line(self, row):
        folder = os.path.dirname(self.path)
        if folder:
            os.makedirs(folder, exist_ok=True)
        with open(self.path, "a", encoding="utf8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    def all(self):
        """Semua trial dengan penilaian rubrik sudah digabung, urutan sesuai waktu tulis."""
        trials, index = [], {}
        for row in self._read_lines():
            if "_update" in row:
                target = index.get(row["_update"])
                if target is not None and isinstance(row.get("changes"), dict):
                    target.update(row["changes"])
                continue
            trial_id = row.get("id")
            if not trial_id or trial_id in index:
                continue
            index[trial_id] = row
            trials.append(row)
        return trials

    def get(self, trial_id):
        return next((t for t in self.all() if t["id"] == trial_id), None)

    def append(self, trial):
        trial = dict(trial)
        trial.setdefault("id", new_trial_id())
        trial.setdefault("recorded_at_utc", utc_now_iso())
        self._write_line(trial)
        return trial

    def update(self, trial_id, changes):
        """Gabungkan perubahan (mis. nilai rubrik) ke satu trial. False bila id tidak ada."""
        if self.get(trial_id) is None:
            return False
        self._write_line({"_update": trial_id, "changes": dict(changes), "_at": utc_now_iso()})
        return True

    def import_text(self, text):
        """Gabungkan berkas JSONL hasil unduhan. Trial dengan id yang sudah ada dilewati. Mengembalikan (ditambah, dilewati)."""
        known = {t["id"] for t in self.all()}
        added = skipped = 0
        for line in (text or "").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError:
                skipped += 1
                continue
            if not isinstance(row, dict):
                skipped += 1
            elif "_update" in row:
                if row["_update"] in known:
                    self._write_line(row)
                else:
                    skipped += 1
            elif row.get("id") and row["id"] not in known:
                self._write_line(row)
                known.add(row["id"])
                added += 1
            else:
                skipped += 1
        return added, skipped

    def to_jsonl(self):
        """Isi gabungan (tanpa baris _update) untuk diunduh."""
        return "".join(json.dumps(t, ensure_ascii=False) + "\n" for t in self.all())


def trials_to_csv(trials):
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for trial in trials:
        row = {}
        for field in CSV_FIELDS:
            value = trial.get(field)
            row[field] = "; ".join(value) if isinstance(value, list) else ("" if value is None else value)
        writer.writerow(row)
    return buffer.getvalue()
