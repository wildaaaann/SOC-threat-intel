"""Rekap evaluasi: MTTR dan ketepatan per kelompok (manual vs platform) dan per model AI.

Hanya statistik deskriptif. Jumlah trial kecil, jadi angka ini belum menyatakan signifikansi apa pun;
jenis uji statistik menunggu keputusan dosen. Modul ini murni (tanpa Streamlit).
"""

import statistics

CONDITION_LABEL = {"manual": "Manual", "platform": "Platform"}


def score_decision(decision_verdict, decision_action, truth):
    """(verdict_benar, aksi_benar) terhadap kunci jawaban; (None, None) bila tidak ada kunci jawaban."""
    if not truth:
        return None, None
    return decision_verdict == truth["verdict"], decision_action in truth["correct_actions"]


def ai_is_correct(ai_verdict, truth):
    """True/False bila ada kunci jawaban; verdict AI yang tidak terbaca dihitung salah. None bila tidak ada kunci."""
    if not truth:
        return None
    return ai_verdict == truth["verdict"]


def scored(trials):
    """Trial skenario yang punya kunci jawaban. Hanya ini yang masuk perhitungan ketepatan."""
    return [t for t in trials if t.get("scenario_id") and t.get("ground_truth_verdict")]


def _stats(values):
    values = [v for v in values if isinstance(v, (int, float))]
    if not values:
        return {"n": 0, "median": None, "mean": None, "q1": None, "q3": None}
    quartiles = statistics.quantiles(values, n=4, method="inclusive") if len(values) >= 2 else [values[0]] * 3
    return {"n": len(values), "median": statistics.median(values), "mean": statistics.fmean(values), "q1": quartiles[0], "q3": quartiles[2]}


def _percent(trials, key):
    known = [t[key] for t in trials if t.get(key) is not None]
    return (100.0 * sum(1 for v in known if v) / len(known)) if known else None


def _mean(trials, key):
    values = [t[key] for t in trials if isinstance(t.get(key), (int, float))]
    return statistics.fmean(values) if values else None


def summarize_conditions(trials):
    """Satu baris per kelompok (manual, platform) dari trial skenario."""
    rows = []
    data = scored(trials)
    for condition in ("manual", "platform"):
        group = [t for t in data if t.get("condition") == condition]
        mttr = _stats([t.get("mttr_s") for t in group])
        rows.append({
            "Kelompok": CONDITION_LABEL[condition],
            "n trial": len(group),
            "n analis": len({t.get("participant") for t in group}),
            "MTTR median (s)": mttr["median"],
            "MTTR rata-rata (s)": mttr["mean"],
            "MTTR Q1 (s)": mttr["q1"],
            "MTTR Q3 (s)": mttr["q3"],
            "Verdict benar (%)": _percent(group, "verdict_correct"),
            "Aksi benar (%)": _percent(group, "action_correct"),
            "Rubrik bukti (rata-rata)": _mean(group, "rubric_evidence"),
            "Rubrik rekomendasi (rata-rata)": _mean(group, "rubric_recommendation"),
            "n dinilai rubrik": sum(1 for t in group if t.get("rubric_evidence") is not None),
        })
    return rows


def summarize_models(trials):
    """Satu baris per (penyedia, model) untuk trial platform. Jangan menggabungkan model berbeda."""
    groups = {}
    for trial in scored(trials):
        if trial.get("condition") == "platform":
            groups.setdefault((trial.get("llm_provider") or "-", trial.get("llm_model") or "-"), []).append(trial)
    rows = []
    for (provider, model), group in sorted(groups.items()):
        mttr = _stats([t.get("mttr_s") for t in group])
        latency = _stats([t.get("system_latency_s") for t in group])
        rows.append({
            "Penyedia": provider,
            "Model": model,
            "n trial": len(group),
            "MTTR median (s)": mttr["median"],
            "Latensi sistem median (s)": latency["median"],
            "Verdict analis benar (%)": _percent(group, "verdict_correct"),
            "Verdict AI benar (%)": _percent(group, "ai_correct"),
            "Verdict AI tidak terbaca (%)": 100.0 * sum(1 for t in group if t.get("ai_verdict") == "Tidak terbaca") / len(group),
            "Format 3 lapis lengkap (%)": _percent(group, "report_layers_ok"),
        })
    return rows


def paired_comparison(trials):
    """Selisih MTTR (platform dikurangi manual) untuk pasangan analis x skenario yang mengerjakan kedua kondisi.

    Nilai negatif berarti platform lebih cepat. Bila satu kondisi dikerjakan berulang, dipakai median-nya.
    """
    cells = {}
    for trial in scored(trials):
        if isinstance(trial.get("mttr_s"), (int, float)) and trial.get("condition") in CONDITION_LABEL:
            cells.setdefault((trial.get("participant"), trial["scenario_id"], trial["condition"]), []).append(trial["mttr_s"])
    diffs = []
    for (participant, scenario, condition), values in cells.items():
        if condition != "platform":
            continue
        other = cells.get((participant, scenario, "manual"))
        if other:
            diffs.append(statistics.median(values) - statistics.median(other))
    return {
        "n pasangan": len(diffs),
        "selisih median (s)": statistics.median(diffs) if diffs else None,
        "selisih rata-rata (s)": statistics.fmean(diffs) if diffs else None,
        "pasangan platform lebih cepat": sum(1 for d in diffs if d < 0),
    }


def data_quality(trials):
    """Hal yang membuat angka evaluasi harus dibaca hati-hati."""
    data = scored(trials)
    platform = [t for t in data if t.get("condition") == "platform"]
    return {
        "trial total": len(trials),
        "trial skenario berkunci": len(data),
        "trial ad hoc (tanpa kunci jawaban, tidak dihitung)": len(trials) - len(data),
        "platform memakai penyedia cadangan": sum(1 for t in platform if t.get("llm_fallback_used")),
        "platform dengan verifikasi SSL mati": sum(1 for t in platform if t.get("tls_verify") is False),
        "platform mode Dibantu (status bocor ke AI)": sum(1 for t in platform if str(t.get("analysis_mode", "")).startswith("Dibantu")),
        "belum dinilai rubrik": sum(1 for t in data if t.get("rubric_evidence") is None),
    }


def format_rows(rows):
    """Angka -> teks siap tampil: None jadi 'n/a', desimal dibulatkan."""
    out = []
    for row in rows:
        formatted = {}
        for key, value in row.items():
            if value is None:
                formatted[key] = "n/a"
            elif isinstance(value, float):
                formatted[key] = f"{value:.1f}"
            else:
                formatted[key] = value
        out.append(formatted)
    return out
