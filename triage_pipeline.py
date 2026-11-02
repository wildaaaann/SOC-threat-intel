"""Pipeline triage: ekstraksi IoC, pengayaan CTI, laporan AI. Dipakai bersama oleh app.py dan worker.py.

Modul ini murni (tanpa Streamlit). Dua tahap dipisah agar UI bisa menampilkan dua langkah:
`enrich` (CTI + prompt) lalu `generate_report` (rantai penyedia AI).
Teks mentah alert hanya dipakai untuk mengekstrak IoC dan tidak pernah masuk ke prompt.
"""

import json
from datetime import datetime

import requests

from cti import (defang_ioc, generate_initial_verdict, get_ioc_type, query_abuseipdb, query_hybridanalysis,
                 query_tip_neiki, query_urlscan, query_virustotal, query_virustotal_relationships, run_cti)
from ioc_extract import extract_iocs, first_public_ip, pick_primary
from llm_providers import run_chain
from triage_prompt import generate_prompt
from triage_report import layers_complete, layers_status


def enrich(*, alert_name, ioc_input, related_ip, raw_text, action, alert_fields, prompt_status, keys, verify, cache=None):
    """Ekstrak IoC, query semua sumber CTI, dan susun prompt.

    `keys` = {"vt", "abuse", "urlscan", "hybrid"}. `prompt_status` None = mode Blind (status analis tidak masuk prompt).
    Mengembalikan dict konteks, atau {"error": pesan}.
    """
    extracted_iocs = extract_iocs(raw_text)
    ioc = (ioc_input or "").strip() or (pick_primary(extracted_iocs) or "")
    if not alert_name or not ioc:
        return {"error": "Alert Name dan Primary IoC wajib diisi (atau tempel Raw Alert yang berisi IoC publik)!"}
    ioc_type = get_ioc_type(ioc)
    if ioc_type == "unknown":
        return {"error": f"Tidak dapat mendeteksi tipe IoC untuk: '{ioc}'. Pastikan formatnya benar."}

    target_ip = ioc if ioc_type == 'ip' else ((related_ip or "").strip() or first_public_ip(extracted_iocs) or "")
    is_hash = ioc_type in ["md5", "sha1", "sha256"]
    cti_log = []

    vt = run_cti(cti_log, "VirusTotal", ioc, True, query_virustotal, ioc, ioc_type, keys["vt"], verify, cache=cache)
    vt_rel = run_cti(cti_log, "VirusTotal (relationships)", ioc, True, query_virustotal_relationships, ioc, ioc_type, keys["vt"], verify, cache=cache)
    abuse = run_cti(cti_log, "AbuseIPDB", target_ip or "n/a", bool(target_ip), query_abuseipdb, target_ip, keys["abuse"], verify, cache=cache)
    urlscan = run_cti(cti_log, "URLScan", ioc, ioc_type in ['domain', 'ip'], query_urlscan, ioc, ioc_type, keys["urlscan"], verify, cache=cache)
    hybrid = run_cti(cti_log, "HybridAnalysis", ioc, is_hash, query_hybridanalysis, ioc, ioc_type, keys["hybrid"], verify, cache=cache)
    tip = run_cti(cti_log, "TIP Neiki", ioc, is_hash, query_tip_neiki, ioc, ioc_type, verify, cache=cache)

    first_seen, last_seen = "N/A", "N/A"
    try:
        vt_dict = json.loads(vt)
        if vt_dict.get('last_analysis_date'):
            last_seen = datetime.fromtimestamp(vt_dict['last_analysis_date']).strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        pass

    initial_verdict = generate_initial_verdict(ioc_type, vt, abuse)

    collated = f"VirusTotal Data:\n{vt}\n"
    if vt_rel: collated += f"\nVirusTotal Relationships:\n{json.dumps(vt_rel, indent=2)}\n"
    if abuse: collated += f"\nAbuseIPDB Data:\n{abuse}\n"
    if urlscan: collated += f"\nURLScan Data:\n{urlscan}\n"
    if hybrid: collated += f"\nHybridAnalysis Data:\n{hybrid}\n"
    if tip: collated += f"\nTIP Neiki Data:\n{tip}\n"

    # Hanya IoC hasil ekstraksi dan kolom alert yang aman yang ikut ke prompt. Teks mentah alert tidak dikirim ke AI.
    other_iocs = [i for i in extracted_iocs if i["value"] != ioc]
    if other_iocs:
        collated += "\nOther IoCs extracted from the alert (not enriched):\n"
        collated += "\n".join(f"- {i['type']}: {i['value']}" + ("" if i["public"] else " (private/non-routable)") for i in other_iocs) + "\n"
    collated += "\nCTI Retrieval Log (UTC):\n"
    collated += "\n".join(f"- {r['Sumber']} | query: {r['Query']} | {r['Waktu (UTC)']} | {r['Status']}: {r['Temuan']}" for r in cti_log) + "\n"

    final_prompt = generate_prompt(alert_name, ioc, ioc_type, action, collated, initial_verdict, first_seen, last_seen, prompt_status, alert_fields)
    return {
        "ioc": ioc, "ioc_type": ioc_type, "alert_name": alert_name, "extracted_iocs": extracted_iocs, "target_ip": target_ip,
        "cti_log": cti_log, "collated": collated, "final_prompt": final_prompt, "initial_verdict": initial_verdict,
        "cti_raw": (vt, vt_rel, abuse, urlscan, hybrid, tip),
    }


def generate_report(ctx, attempts, gemini_fn, verify, post=requests.post):
    """Jalankan rantai penyedia AI untuk satu konteks hasil `enrich`."""
    report, used, llm_log = run_chain(ctx["final_prompt"], attempts, gemini_fn, verify=verify, post=post)
    if report is None:
        detail = " | ".join(f"{r['Penyedia']}: {r['Detail']}" for r in llm_log)
        report = f"Terjadi kesalahan saat menghubungi penyedia AI. {detail}"
        used = {"provider": "-", "model": "-"}
    cert_failed = any("certificate_verify_failed" in str(r).lower() for r in (*ctx["cti_raw"], report))
    return {
        "report": report, "llm_used": used, "llm_log": llm_log,
        "llm_fallback_used": bool(llm_log) and llm_log[0]["Status"] != "OK",
        "cert_failed": cert_failed, "layers": layers_status(report), "layers_ok": layers_complete(report),
    }
