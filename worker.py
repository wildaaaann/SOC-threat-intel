"""Worker Mode Otomatis: alert Wazuh masuk sendiri, diperkaya CTI, ditulis AI, dan disimpan sebagai tiket.

Dijalankan sebagai proses terpisah dari Streamlit (mis. systemd di server Wazuh), karena Streamlit hanya bekerja
saat halaman dibuka:

    python3 worker.py            # berjalan terus, polling tiap WORKER_POLL_SECONDS
    python3 worker.py --once     # satu putaran lalu keluar (uji coba atau cron)

Semua pengaturan lewat variabel lingkungan (lihat deploy/worker.env.example). Kredensial tidak pernah dicetak.
Modul ini murni (tanpa Streamlit) dan tidak mengimpor app.py.

Aturan keselamatan ada di ticket_policy.decide: AI hanya menutup tiket bila hasilnya lengkap dan konsisten.
Selebihnya tiket berstatus "Perlu manusia", tidak pernah dibuang diam-diam.
"""

import argparse
import hashlib
import json
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import requests

import cti
from llm_providers import OPENAI_COMPATIBLE, build_attempts, gemini_generate
from ticket_policy import build_ticket
from ticket_store import TicketStore, read_worker_state, write_worker_state
from triage_pipeline import enrich, generate_report
from wazuh_client import WazuhError, alert_to_inputs, extract_entities, fetch_alerts_since, parse_timestamp

_TRUE = ("1", "true", "yes", "on")


@dataclass
class Config:
    indexer_url: str
    indexer_user: str
    indexer_password: str
    indexer_verify: object = True          # True atau path root-ca.pem
    verify: bool = True                    # verifikasi TLS untuk CTI dan AI
    min_level: int = 7
    poll_seconds: int = 60
    max_per_cycle: int = 20
    lookback_min: int = 15
    overlap_s: int = 120
    tickets_path: str = "data/tickets.jsonl"
    state_path: str = "data/worker_state.json"
    cache_path: str = "data/cti_cache.json"
    cache_ttl_s: int = 86400
    vt_interval_s: float = 16.0
    keys: dict = field(default_factory=dict)
    gemini_key: object = ()  # daftar key Gemini yang terisi (satu atau dua akun)
    gemini_model: str = ""
    gemini_fallback_models: object = ()  # model Gemini cadangan, dicoba bila model utama gagal
    llm_extra: dict = field(default_factory=dict)
    llm_fallback: bool = True
    cache: object = None


def load_config(env):
    """Baca Config dari variabel lingkungan. ValueError berisi semua yang kurang, supaya satu kali perbaikan cukup."""
    missing = [name for name in ("WAZUH_INDEXER_URL", "WAZUH_USER", "WAZUH_PASSWORD", "VT_API_KEY") if not env.get(name)]
    llm_extra = {
        name: {"key": env.get(var, ""), "model": env.get(f"{var.split('_')[0]}_MODEL", "")}
        for name, var in (("NVIDIA NIM", "NVIDIA_API_KEY"), ("Groq", "GROQ_API_KEY"), ("OpenRouter", "OPENROUTER_API_KEY"))
    }
    if not (env.get("GEMINI_API_KEY") or env.get("GEMINI_API_KEY_2")) and not any(v["key"] for v in llm_extra.values()):
        missing.append("minimal satu key AI (GEMINI_API_KEY, NVIDIA_API_KEY, GROQ_API_KEY, atau OPENROUTER_API_KEY)")
    if missing:
        raise ValueError("Konfigurasi belum lengkap: " + ", ".join(missing))

    data_dir = env.get("DATA_DIR", "data")
    tickets_path = env.get("TICKETS_PATH", os.path.join(data_dir, "tickets.jsonl"))
    state_dir = os.path.dirname(tickets_path) or "."  # UI membaca status worker dari folder tiket yang sama
    cfg = Config(
        indexer_url=env["WAZUH_INDEXER_URL"], indexer_user=env["WAZUH_USER"], indexer_password=env["WAZUH_PASSWORD"],
        indexer_verify=env.get("WAZUH_CA") or True,
        verify=env.get("WORKER_TLS_VERIFY", "true").lower() in _TRUE,
        min_level=int(env.get("WORKER_MIN_LEVEL", "7")),
        poll_seconds=int(env.get("WORKER_POLL_SECONDS", "60")),
        max_per_cycle=int(env.get("WORKER_MAX_PER_CYCLE", "20")),
        lookback_min=int(env.get("WORKER_LOOKBACK_MINUTES", "15")),
        tickets_path=tickets_path,
        state_path=os.path.join(state_dir, "worker_state.json"),
        cache_path=os.path.join(state_dir, "cti_cache.json"),
        vt_interval_s=float(env.get("VT_MIN_INTERVAL_S", "16")),
        keys={"vt": env["VT_API_KEY"], "abuse": env.get("ABUSEIPDB_API_KEY", ""),
              "urlscan": env.get("URLSCAN_API_KEY", ""), "hybrid": env.get("HYBRID_API_KEY", "")},
        gemini_key=[k for k in (env.get("GEMINI_API_KEY", ""), env.get("GEMINI_API_KEY_2", "")) if k], gemini_model=env.get("GEMINI_MODEL", ""), llm_extra=llm_extra,
        gemini_fallback_models=[m.strip() for m in env.get("GEMINI_FALLBACK_MODELS", "").split(",") if m.strip()],
        llm_fallback=env.get("WORKER_LLM_FALLBACK", "true").lower() in _TRUE,
    )
    cfg.cache = cti.CtiCache(cfg.cache_path, cfg.cache_ttl_s)
    return cfg


def _log(message):
    print(f"[{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}Z] {message}", flush=True)


def _alert_id(alert):
    if alert.get("id"):
        return alert["id"]
    digest = hashlib.sha1(json.dumps(alert.get("raw", {}), sort_keys=True, default=str).encode("utf8")).hexdigest()[:16]
    return f"w-{digest}"


def process_alert(alert, cfg, *, post=requests.post, gemini_fn=None):
    """Satu alert menjadi satu tiket. Tidak ada langkah manusia di dalamnya."""
    started = time.monotonic()
    inputs = alert_to_inputs(alert)
    entities = extract_entities(alert)
    # prompt_status=None: AI selalu menilai sendiri, tidak pernah menerima status dari siapa pun.
    ctx = enrich(
        alert_name=inputs["alert_name"], ioc_input="", related_ip="", raw_text=inputs["raw_text"], action=inputs["action"],
        alert_fields=inputs["llm_facts"], prompt_status=None, keys=cfg.keys, verify=cfg.verify, cache=cfg.cache,
    )
    gen = None
    if "error" not in ctx:
        fn = gemini_fn or (lambda prompt, key, model: gemini_generate(prompt, key, model, verify=cfg.verify))
        gen = generate_report(ctx, build_attempts(cfg.gemini_key, cfg.llm_extra, cfg.llm_fallback, gemini_model=cfg.gemini_model, gemini_fallback_models=cfg.gemini_fallback_models), fn, cfg.verify, post=post)
    return build_ticket(alert, entities, ctx, gen, tls_verify=cfg.verify, processing_s=time.monotonic() - started)


def _iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse_iso(value):
    return parse_timestamp(value) if value else None


def run_cycle(cfg, store, *, fetch=fetch_alerts_since, process=process_alert, now=None):
    """Satu putaran: ambil alert baru, proses yang belum pernah diproses, perbarui kursor dan detak jantung."""
    now = now or datetime.now(timezone.utc)
    state = read_worker_state(cfg.state_path)
    cursor = _parse_iso(state.get("cursor_utc")) or (now - timedelta(minutes=cfg.lookback_min))
    state.update({"last_cycle_utc": now.strftime("%Y-%m-%d %H:%M:%S"), "poll_seconds": cfg.poll_seconds, "min_level": cfg.min_level})
    processed = 0

    try:
        fetch_size = max(cfg.max_per_cycle * 5, 50)
        alerts = fetch(cfg.indexer_url, cfg.indexer_user, cfg.indexer_password, cursor - timedelta(seconds=cfg.overlap_s),
                       verify=cfg.indexer_verify, min_level=cfg.min_level, size=fetch_size)
    except WazuhError as exc:
        state["last_error"] = str(exc)
        write_worker_state(cfg.state_path, state)
        _log(f"Wazuh Indexer gagal: {exc}")
        return {"processed": 0, "error": str(exc)}

    known = store.known_ids()
    fresh = []
    for alert in alerts:
        alert["id"] = _alert_id(alert)
        if alert["id"] not in known:
            fresh.append(alert)
    batch = fresh[:cfg.max_per_cycle]

    for alert in batch:
        try:
            ticket = process(alert, cfg)
        except Exception as exc:  # satu alert bermasalah tidak boleh menghentikan antrean atau hilang diam-diam
            ticket = build_ticket(alert, extract_entities(alert), {"error": f"Galat tak terduga saat memproses: {str(exc)[:160]}"}, None,
                                  tls_verify=cfg.verify, processing_s=0)
        store.append(ticket)
        known.add(ticket["id"])
        processed += 1
        _log(f"tiket {ticket['id']} | {ticket['status']} | {ticket['ai_verdict']} | {ticket['severity']} | review: {ticket['review_priority']}")

    # Kursor maju sampai alert terakhir yang sudah ditangani. Bila antrean menumpuk, berhenti di alert terakhir yang diproses.
    backlog = len(fresh) > len(batch)
    marker = batch[-1] if backlog else (alerts[-1] if alerts else None)
    moved = parse_timestamp(marker.get("timestamp")) if marker else None
    if moved and moved > cursor:
        cursor = moved
    elif not alerts:
        cursor = max(cursor, now)
    state.update({
        "cursor_utc": _iso(cursor), "last_error": "", "processed_last_cycle": processed,
        "processed_total": int(state.get("processed_total", 0)) + processed, "backlog": backlog,
    })
    write_worker_state(cfg.state_path, state)
    return {"processed": processed, "backlog": backlog}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Worker Mode Otomatis: alert Wazuh menjadi tiket yang diperkaya AI")
    parser.add_argument("--once", action="store_true", help="satu putaran lalu keluar")
    args = parser.parse_args(argv)
    try:
        cfg = load_config(os.environ)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    cti.set_min_interval("virustotal", cfg.vt_interval_s)
    if not cfg.verify:
        _log("PERINGATAN: WORKER_TLS_VERIFY mati. Request CTI dan AI tidak memeriksa sertifikat, dan setiap tiket mencatatnya.")
    store = TicketStore(cfg.tickets_path)
    stop = {"now": False}
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.update(now=True))

    _log(f"Worker mulai. Level minimum {cfg.min_level}, polling {cfg.poll_seconds} detik, tiket di {cfg.tickets_path}")
    while not stop["now"]:
        result = run_cycle(cfg, store)
        if args.once:
            break
        for _ in range(cfg.poll_seconds):
            if stop["now"]:
                break
            time.sleep(1)
    _log("Worker berhenti.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
