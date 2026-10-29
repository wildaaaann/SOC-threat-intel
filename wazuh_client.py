"""Mengambil alert Wazuh dan mengubahnya menjadi masukan analisis.

Sumber alert:
- Wazuh Indexer (OpenSearch), indeks `wazuh-alerts-*`, port 9200 secara default. Alert Wazuh disimpan di sini,
  bukan di REST API manager (port 55000). [Kemungkinan Besar; cocokkan dengan versi Wazuh di lab Anda]
- Berkas ekspor: `alerts.json` dari manager (NDJSON), ekspor Discover, atau array JSON.

Modul ini murni (tanpa Streamlit); `post` bisa diganti saat tes. Belum diuji terhadap server Wazuh sungguhan:
tes memakai respons palsu.
"""

import json
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

# Hanya kolom ini yang boleh sampai ke LLM. Identitas agent, lokasi log, dan full_log tidak ikut.
LLM_SAFE_FIELDS = ("rule_id", "rule_description", "rule_level", "rule_groups", "mitre_ids", "mitre_techniques", "decoder", "timestamp")


class WazuhError(Exception):
    """Kesalahan yang pesannya aman ditampilkan ke analis (tanpa kredensial)."""


def _get(doc, dotted, default=None):
    """Baca 'rule.level' dari dict bersarang, atau dari kunci datar 'rule.level' (ekspor tertentu)."""
    if not isinstance(doc, dict):
        return default
    if dotted in doc:
        return doc[dotted]
    node = doc
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


def _as_list(value):
    if value is None or value == "":
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def normalize_alert(source, doc_id=None):
    """Ubah satu dokumen alert Wazuh menjadi dict datar. `source` boleh berisi pembungkus `_source`."""
    if isinstance(source, dict) and isinstance(source.get("_source"), dict):
        doc_id = doc_id or source.get("_id")
        source = source["_source"]
    if not isinstance(source, dict):
        raise WazuhError("Isi alert bukan objek JSON")

    data = _get(source, "data", {})
    return {
        "id": str(doc_id or source.get("id") or ""),
        "timestamp": str(_get(source, "timestamp", "") or ""),
        "rule_id": str(_get(source, "rule.id", "") or ""),
        "rule_description": str(_get(source, "rule.description", "") or ""),
        "rule_level": _get(source, "rule.level"),
        "rule_groups": [str(g) for g in _as_list(_get(source, "rule.groups"))],
        "mitre_ids": [str(x) for x in _as_list(_get(source, "rule.mitre.id"))],
        "mitre_techniques": [str(x) for x in _as_list(_get(source, "rule.mitre.technique"))],
        "agent_name": str(_get(source, "agent.name", "") or ""),
        "agent_ip": str(_get(source, "agent.ip", "") or ""),
        "decoder": str(_get(source, "decoder.name", "") or ""),
        "location": str(_get(source, "location", "") or ""),
        "full_log": str(_get(source, "full_log", "") or ""),
        "data": data if isinstance(data, dict) else {},
        "raw": source,
    }


def _check_base_url(base_url):
    parsed = urlparse((base_url or "").strip())
    if parsed.scheme not in ("https", "http") or not parsed.netloc:
        raise WazuhError("URL Wazuh Indexer harus diawali https:// (contoh: https://192.168.1.10:9200)")
    return base_url.strip().rstrip("/")


def build_query(size=50, min_level=7, hours=24, query=""):
    filters = [
        {"range": {"rule.level": {"gte": int(min_level)}}},
        {"range": {"timestamp": {"gte": f"now-{int(hours)}h"}}},
    ]
    bool_query = {"filter": filters}
    if query and query.strip():
        bool_query["must"] = [{"query_string": {"query": query.strip()}}]
    return {"size": int(size), "sort": [{"timestamp": {"order": "desc"}}], "query": {"bool": bool_query}}


def fetch_alerts(base_url, username, password, *, verify=True, size=50, min_level=7, hours=24, query="",
                 index="wazuh-alerts-*", post=requests.post, timeout=30):
    """Ambil alert terbaru dari Wazuh Indexer. `verify` boleh True/False atau path berkas CA."""
    base = _check_base_url(base_url)
    if not username or not password:
        raise WazuhError("Username dan password Wazuh Indexer wajib diisi")
    try:
        response = post(
            f"{base}/{index}/_search",
            auth=(username, password),
            json=build_query(size, min_level, hours, query),
            headers={"Content-Type": "application/json"},
            timeout=timeout,
            verify=verify,
        )
    except requests.exceptions.SSLError as exc:
        raise WazuhError(
            "CERTIFICATE_VERIFY_FAILED: sertifikat Wazuh Indexer tidak dipercaya. Indexer di lab biasanya memakai sertifikat "
            "self-signed; isi 'Path CA Wazuh' dengan root-ca.pem miliknya. " + str(exc)[:120]
        )
    except requests.exceptions.RequestException as exc:
        raise WazuhError(f"Tidak bisa menghubungi Wazuh Indexer: {str(exc)[:160]}")

    status = getattr(response, "status_code", 200)
    if status == 401:
        raise WazuhError("Kredensial ditolak oleh Wazuh Indexer (HTTP 401)")
    if status == 403:
        raise WazuhError("Akun tidak punya izin membaca indeks alert (HTTP 403)")
    if status == 404:
        raise WazuhError(f"Indeks '{index}' tidak ditemukan (HTTP 404). Pastikan ini Wazuh Indexer (port 9200), bukan API manager (port 55000)")
    if status >= 400:
        raise WazuhError(f"Wazuh Indexer menjawab HTTP {status}")

    try:
        hits = response.json()["hits"]["hits"]
    except (KeyError, TypeError, ValueError):
        raise WazuhError("Format jawaban Wazuh Indexer tidak dikenali (tidak ada hits.hits)")
    return [normalize_alert(hit) for hit in hits]


def parse_alerts_file(text):
    """Baca berkas ekspor alert: array JSON, objek hits.hits, satu objek alert, atau NDJSON."""
    text = (text or "").strip()
    if not text:
        raise WazuhError("Berkas kosong")

    docs = []
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            docs = parsed
        elif isinstance(parsed, dict) and isinstance(_get(parsed, "hits.hits"), list):
            docs = parsed["hits"]["hits"]
        else:
            docs = [parsed]
    except ValueError:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                docs.append(json.loads(line))
            except ValueError:
                continue

    alerts = []
    for doc in docs:
        try:
            alerts.append(normalize_alert(doc))
        except WazuhError:
            continue
    if not alerts:
        raise WazuhError("Tidak ada alert yang bisa dibaca. Format yang didukung: array JSON, hasil Discover, atau satu alert per baris (alerts.json)")
    return alerts


def parse_timestamp(value):
    """Timestamp alert Wazuh ("2026-10-29T03:15:42.123+0000") menjadi datetime UTC; None bila tidak terbaca."""
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(text, fmt).astimezone(timezone.utc)
        except ValueError:
            continue
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def alert_label(alert):
    level = alert.get("rule_level")
    return f"[{alert.get('timestamp', '')[:19]}] L{level if level is not None else '?'} | {alert.get('rule_description') or '(tanpa deskripsi)'} (rule {alert.get('rule_id') or '?'})"


def _flatten_values(value, out):
    if isinstance(value, dict):
        for item in value.values():
            _flatten_values(item, out)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _flatten_values(item, out)
    elif value is not None:
        out.append(str(value))


def alert_to_inputs(alert):
    """Masukan analisis dari satu alert.

    - alert_name: deskripsi rule + ID.
    - raw_text: full_log + isi `data`, HANYA untuk ekstraksi IoC di sisi aplikasi. Tidak dikirim ke LLM.
    - llm_facts: baris "Label: nilai" dari kolom LLM_SAFE_FIELDS, satu-satunya isi alert yang ikut ke LLM.
    """
    values = []
    _flatten_values(alert.get("data", {}), values)
    raw_text = "\n".join([alert.get("full_log", "")] + values).strip()

    facts = []
    labels = {
        "rule_id": "Rule ID", "rule_description": "Rule description", "rule_level": "Rule level",
        "rule_groups": "Rule groups", "mitre_ids": "MITRE ATT&CK IDs", "mitre_techniques": "MITRE techniques",
        "decoder": "Decoder", "timestamp": "Alert timestamp",
    }
    for key in LLM_SAFE_FIELDS:
        value = alert.get(key)
        if value in (None, "", []):
            continue
        facts.append(f"{labels[key]}: {', '.join(value) if isinstance(value, list) else value}")

    name = alert.get("rule_description") or "Wazuh alert"
    if alert.get("rule_id"):
        name = f"{name} (rule {alert['rule_id']})"
    return {"alert_name": name, "raw_text": raw_text, "llm_facts": facts, "action": ""}
