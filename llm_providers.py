"""Rantai penyedia LLM gratis dengan fallback.

Modul ini murni: tanpa Streamlit, jadi bisa diuji dengan `python3 -m unittest`.
Urutan percobaan = urutan list `attempts`. Satu penyedia gagal (429, 5xx, timeout, key salah,
respons kosong) -> lanjut ke penyedia berikutnya. Setiap percobaan dicatat di log.
"""

import re
import time
from datetime import datetime, timezone

import requests

# Semua penyedia ini memakai format OpenAI `/chat/completions`. Gemini dipanggil lewat `gemini_fn` dari app.
# Nama model hanya nilai awal dan bisa diubah di sidebar: katalog model gratis sering berganti.
OPENAI_COMPATIBLE = {
    "NVIDIA NIM": {"base_url": "https://integrate.api.nvidia.com/v1", "model": "mistralai/mistral-large-4-1t-a52b"},
    "Groq": {"base_url": "https://api.groq.com/openai/v1", "model": "openai/gpt-oss-120b"},
    # "openrouter/free" memilih sendiri satu model gratis yang sedang tersedia. Model yang benar-benar menjawab
    # dicatat dari respons (lihat run_chain), karena akurasi harus dihitung per model.
    "OpenRouter": {"base_url": "https://openrouter.ai/api/v1", "model": "openrouter/free"},
}
# Nama model gratis sering dipensiunkan (gemini-2.5-flash dan llama-3.3-70b sudah gagal di tiga penyedia).
# Nilai ini hanya titik awal; tombol "Cek model yang tersedia" di sidebar membaca daftar model langsung dari penyedia.
GEMINI_MODEL = "gemini-3.8-flash"

_THINK = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


class LLMError(Exception):
    """Kegagalan satu penyedia yang layak dicoba ulang di penyedia lain."""


def build_attempts(gemini_key, extra, fallback=True, gemini_model=None, gemini_fallback_models=None):
    """Susun urutan percobaan.

    `extra` = {nama_penyedia: {"key": ..., "model": ...}}. Penyedia tanpa key dilewati.
    `gemini_key` boleh satu string atau daftar key (mis. dari dua akun). Tiap key menjadi satu percobaan Gemini
    berurutan; semuanya tetap penyedia "Gemini" dengan model yang sama, jadi akurasinya sah digabung.
    `gemini_fallback_models` (daftar nama) = model Gemini cadangan, dicoba setelah model utama gagal di semua key.
    Urutannya per model: model utama (key #1, #2), lalu tiap model cadangan (key #1, #2). Tiap percobaan mencatat
    modelnya sendiri, jadi akurasi tetap dihitung per model dan tidak pernah digabung.
    Gemini selalu pertama. Jika `fallback` False, hanya penyedia dan model pertama yang dipakai, termasuk semua
    key-nya, karena memutar key tidak mengganti model; model cadangan ikut dibuang.
    """
    attempts = []
    keys = [gemini_key] if isinstance(gemini_key, str) else list(gemini_key or [])
    seen_keys = []
    for key in keys:
        if key and key not in seen_keys:
            seen_keys.append(key)
    primary = (gemini_model or GEMINI_MODEL).strip()
    models = [primary]
    for name in gemini_fallback_models or []:
        name = (name or "").strip()
        if name and name not in models:
            models.append(name)
    for model in models:
        for slot, key in enumerate(seen_keys, 1):
            attempts.append({"provider": "Gemini", "model": model, "key": key, "kind": "gemini", "slot": f"#{slot}"})
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
    if fallback or not attempts:
        return attempts
    first = attempts[0]
    return [a for a in attempts if (a["provider"], a["model"]) == (first["provider"], first["model"])]


def _error_message(response):
    """Pesan error dari badan respons penyedia (mis. 'model requires terms acceptance'), dipotong. Badan error
    penyedia tidak memuat API key kita; key hanya ada di header request yang tidak dibaca di sini."""
    try:
        body = response.json()
        err = body.get("error") if isinstance(body, dict) else None
        message = err.get("message") if isinstance(err, dict) else (err or None)
    except Exception:
        message = None
    message = message or getattr(response, "text", "") or "tanpa pesan"
    return " ".join(str(message).split())[:160]


# Error sementara (lonjakan permintaan, server sibuk, timeout): satu kali ulang pada model yang sama cukup.
_TRANSIENT = re.compile(r"\b(500|502|503|504)\b|UNAVAILABLE|high demand|timed out|timeout", re.IGNORECASE)


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
    if status in (404, 410):
        raise LLMError(f"Model '{attempt['model']}' tidak tersedia (HTTP {status}); kemungkinan sudah dipensiunkan. Klik 'Cek model yang tersedia' di sidebar lalu ganti nama modelnya")
    if status >= 400:
        raise LLMError(f"HTTP {status}: {_error_message(response)}")
    try:
        body = response.json()
        text = body["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError, ValueError):
        raise LLMError("Format respons tidak dikenali")
    served = body.get("model") if isinstance(body, dict) else None
    if isinstance(served, str) and served and served != attempt["model"]:
        attempt["served_model"] = served  # router (mis. openrouter/free) memilih model; catat yang sebenarnya menjawab
    text = _THINK.sub("", text).strip()  # model penalaran kadang menyertakan <think>...</think>
    if not text:
        raise LLMError("Respons kosong")
    return text


def run_chain(prompt, attempts, gemini_fn, verify=True, post=requests.post, retry_wait=3.0, sleep=None):
    """Coba tiap penyedia berurutan.

    Mengembalikan (teks, attempt_yang_berhasil, log). Jika semua gagal: (None, None, log).
    `gemini_fn(prompt, key, model)` harus mengembalikan teks atau melempar exception.
    """
    log = []
    for attempt in attempts:
        entry = {
            "Penyedia": attempt["provider"],
            "Model": attempt["model"],
            "Kunci": attempt.get("slot", ""),
            "Waktu (UTC)": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        }
        def call_once():
            if attempt["kind"] == "gemini":
                out = gemini_fn(prompt, attempt["key"], attempt["model"])
                if not out or not str(out).strip():
                    raise LLMError("Respons kosong")
                return out
            return call_openai_compatible(prompt, attempt, verify, post=post)

        retried = False
        try:
            try:
                text = call_once()
            except Exception as first:
                if not _TRANSIENT.search(str(first)):
                    raise
                retried = True
                (sleep or time.sleep)(retry_wait)
                text = call_once()
        except Exception as exc:
            entry.update({"Status": "Gagal", "Detail": (str(exc)[:200] + (" (sudah diulang 1x)" if retried else ""))})
            log.append(entry)
            continue
        entry.update({"Status": "OK", "Detail": "berhasil setelah 1x ulang" if retried else ""})
        if attempt.get("served_model"):
            attempt = dict(attempt, model=f"{attempt['model']} -> {attempt['served_model']}")
            entry["Model"] = attempt["model"]
        log.append(entry)
        return text, attempt, log
    return None, None, log


def gemini_generate(prompt, key, model, verify=True):
    """Satu panggilan Gemini. `verify` False hanya bila analis mematikan verifikasi SSL di sidebar."""
    from google import genai
    from google.genai import types

    if verify:
        client = genai.Client(api_key=key)
    else:
        import ssl
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        client = genai.Client(api_key=key, http_options=types.HttpOptions(client_args={'verify': context}))
    return client.models.generate_content(model=model, contents=prompt).text


def list_models(provider, key, verify=True, get=None, timeout=20):
    """Daftar id model yang ditawarkan satu penyedia OpenAI-compatible, untuk memilih nama yang masih berlaku.

    Mengembalikan list id terurut. LLMError (pesan tanpa key) bila gagal. Untuk OpenRouter hanya model gratis.
    """
    cfg = OPENAI_COMPATIBLE.get(provider)
    if not cfg:
        raise LLMError(f"Penyedia tidak dikenal: {provider}")
    get = get or requests.get
    try:
        response = get(cfg["base_url"] + "/models", headers={"Authorization": f"Bearer {key}"}, timeout=timeout, verify=verify)
        status = getattr(response, "status_code", 200)
        if status in (401, 403):
            raise LLMError(f"API key ditolak (HTTP {status})")
        response.raise_for_status()
        ids = [m["id"] for m in response.json().get("data", []) if isinstance(m, dict) and m.get("id")]
    except LLMError:
        raise
    except Exception as exc:
        raise LLMError(f"Gagal membaca daftar model: {type(exc).__name__}") from None
    if provider == "OpenRouter":
        ids = [i for i in ids if i.endswith(":free") or i == "openrouter/free"]
    return sorted(set(ids))
