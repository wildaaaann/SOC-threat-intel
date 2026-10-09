"""Rantai penyedia LLM gratis dengan fallback.

Modul ini murni: tanpa Streamlit, jadi bisa diuji dengan `python3 -m unittest`.
Urutan percobaan = urutan list `attempts`. Satu penyedia gagal (429, 5xx, timeout, key salah,
respons kosong) -> lanjut ke penyedia berikutnya. Setiap percobaan dicatat di log.
"""

import re
from datetime import datetime, timezone

import requests

# Semua penyedia ini memakai format OpenAI `/chat/completions`. Gemini dipanggil lewat `gemini_fn` dari app.
# Nama model hanya nilai awal dan bisa diubah di sidebar: katalog model gratis sering berganti.
OPENAI_COMPATIBLE = {
    "NVIDIA NIM": {"base_url": "https://integrate.api.nvidia.com/v1", "model": "meta/llama-3.3-70b-instruct"},
    "Groq": {"base_url": "https://api.groq.com/openai/v1", "model": "llama-3.3-70b-versatile"},
    "OpenRouter": {"base_url": "https://openrouter.ai/api/v1", "model": "meta-llama/llama-3.3-70b-instruct:free"},
}
GEMINI_MODEL = "gemini-2.5-flash"

_THINK = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


class LLMError(Exception):
    """Kegagalan satu penyedia yang layak dicoba ulang di penyedia lain."""


def build_attempts(gemini_key, extra, fallback=True):
    """Susun urutan percobaan.

    `extra` = {nama_penyedia: {"key": ..., "model": ...}}. Penyedia tanpa key dilewati.
    Gemini selalu pertama bila key-nya ada. Jika `fallback` False, hanya penyedia pertama yang dipakai.
    """
    attempts = []
    if gemini_key:
        attempts.append({"provider": "Gemini", "model": GEMINI_MODEL, "key": gemini_key, "kind": "gemini"})
    for name, cfg in OPENAI_COMPATIBLE.items():
        entry = (extra or {}).get(name) or {}
        if entry.get("key"):
            attempts.append({
                "provider": name,
                "model": (entry.get("model") or cfg["model"]).strip(),
                "key": entry["key"],
                "kind": "openai",
                "base_url": cfg["base_url"],
            })
    return attempts if fallback else attempts[:1]


def call_openai_compatible(prompt, attempt, verify, post=requests.post, timeout=60):
    response = post(
        attempt["base_url"] + "/chat/completions",
        headers={"Authorization": f"Bearer {attempt['key']}", "Content-Type": "application/json"},
        json={"model": attempt["model"], "messages": [{"role": "user", "content": prompt}]},
        timeout=timeout,
        verify=verify,
    )
    status = getattr(response, "status_code", 200)
    if status == 429:
        raise LLMError("Batas pemakaian gratis tercapai (HTTP 429)")
    if status in (401, 403):
        raise LLMError(f"API key ditolak (HTTP {status})")
    response.raise_for_status()
    try:
        text = response.json()["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError, ValueError):
        raise LLMError("Format respons tidak dikenali")
    text = _THINK.sub("", text).strip()  # model penalaran kadang menyertakan <think>...</think>
    if not text:
        raise LLMError("Respons kosong")
    return text


def run_chain(prompt, attempts, gemini_fn, verify=True, post=requests.post):
    """Coba tiap penyedia berurutan.

    Mengembalikan (teks, attempt_yang_berhasil, log). Jika semua gagal: (None, None, log).
    `gemini_fn(prompt, key, model)` harus mengembalikan teks atau melempar exception.
    """
    log = []
    for attempt in attempts:
        entry = {
            "Penyedia": attempt["provider"],
            "Model": attempt["model"],
            "Waktu (UTC)": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        }
        try:
            if attempt["kind"] == "gemini":
                text = gemini_fn(prompt, attempt["key"], attempt["model"])
                if not text or not str(text).strip():
                    raise LLMError("Respons kosong")
            else:
                text = call_openai_compatible(prompt, attempt, verify, post=post)
        except Exception as exc:
            entry.update({"Status": "Gagal", "Detail": str(exc)[:200]})
            log.append(entry)
            continue
        entry.update({"Status": "OK", "Detail": ""})
        log.append(entry)
        return text, attempt, log
    return None, None, log
