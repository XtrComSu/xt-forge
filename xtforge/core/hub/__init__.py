"""HuggingFace Hub: models, datasets and file listings.

Built for the distillation loop, not for browsing. The questions that matter
are "what can run here" (quantisation and file sizes), "what is this model
based on" (base model, license, training data) and "what is worth learning
from" (downloads, likes, task).

    xtforge hub models qwen --gguf
    xtforge hub datasets distill --limit 5
    xtforge hub files TheBloke/Mistral-7B-GGUF
    xtforge hub show Qwen/Qwen2.5-7B-Instruct

The API is public and keyless for public repos.
"""
from __future__ import annotations

from typing import Any

from .. import net

BASE = "https://huggingface.co/api"
TTL = 3600
TOP_TAGS = ("gguf", "ggml", "safetensors", "transformers", "text-generation",
            "text2text-generation", "feature-extraction", "conversational",
            "distillation", "lora", "merge", "quantized", "finetuned")


def _trim_tags(tags: list[str]) -> list[str]:
    keep = [t for t in tags if t in TOP_TAGS or t.startswith("base_model:")]
    return keep[:8]


def _size(value: Any) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return ""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if number < 1024 or unit == "TB":
            return f"{number:.0f}{unit}" if unit in ("B", "KB") else f"{number:.1f}{unit}"
        number /= 1024
    return ""


def _model_row(item: dict[str, Any]) -> dict[str, Any]:
    card = item.get("cardData") or {}
    base = card.get("base_model")
    if isinstance(base, list):
        base = base[0] if base else None
    return {
        "id": item.get("id") or item.get("modelId"),
        "downloads": item.get("downloads"),
        "likes": item.get("likes"),
        "task": item.get("pipeline_tag"),
        "library": item.get("library_name"),
        "gated": bool(item.get("gated")),
        "updated": (item.get("lastModified") or "")[:10],
        "base_model": base,
        "license": card.get("license"),
        "tags": _trim_tags(item.get("tags") or []),
    }


def models(query: str, limit: int = 10, sort: str = "downloads",
           gguf: bool = False, task: str | None = None) -> dict[str, Any]:
    params = [f"search={net.quote(query or '')}", f"limit={max(1, min(limit, 50))}",
              f"sort={net.quote(sort)}", "direction=-1", "full=true"]
    if gguf:
        params.append("filter=gguf")
    if task:
        params.append(f"filter={net.quote(task)}")
    ok, payload, err = net.get_json(f"{BASE}/models?{'&'.join(params)}", ttl=TTL)
    if not ok or not isinstance(payload, list):
        return {"ok": False, "err": err or "unexpected response"}
    rows = [_model_row(item) for item in payload]
    return {"ok": True, "query": query, "count": len(rows),
            "models": rows,
            "note": ("sorted by downloads; use `hub files <id>` to see which "
                     "quantisations actually exist and how big they are")}


def datasets(query: str, limit: int = 10, sort: str = "downloads") -> dict[str, Any]:
    ok, payload, err = net.get_json(
        f"{BASE}/datasets?search={net.quote(query or '')}"
        f"&limit={max(1, min(limit, 50))}&sort={net.quote(sort)}&full=true",
        ttl=TTL)
    if not ok or not isinstance(payload, list):
        return {"ok": False, "err": err or "unexpected response"}
    rows = []
    for item in payload:
        card = item.get("cardData") or {}
        rows.append({"id": item.get("id"), "downloads": item.get("downloads"),
                     "likes": item.get("likes"),
                     "license": card.get("license"),
                     "task_categories": (card.get("task_categories") or [])[:3],
                     "size": card.get("size_categories") or [],
                     "updated": (item.get("lastModified") or "")[:10]})
    return {"ok": True, "query": query, "count": len(rows), "datasets": rows}


def show(repo_id: str) -> dict[str, Any]:
    """Everything the hub knows about one model, minus the marketing."""
    value = (repo_id or "").strip().strip("/")
    if not value:
        return {"ok": False, "err": "show needs a repo id"}
    ok, payload, err = net.get_json(
        f"{BASE}/models/{net.quote(value).replace('%2F', '/')}", ttl=TTL)
    if not ok or not isinstance(payload, dict):
        return {"ok": False, "err": err or "not found", "repo": value}
    card = payload.get("cardData") or {}
    files = payload.get("siblings") or []
    quants = sorted({f.get("rfilename") for f in files
                     if (f.get("rfilename") or "").lower().endswith(".gguf")})
    return {"ok": True, "repo": value,
            "task": payload.get("pipeline_tag"),
            "library": payload.get("library_name"),
            "downloads": payload.get("downloads"),
            "likes": payload.get("likes"),
            "gated": bool(payload.get("gated")),
            "updated": (payload.get("lastModified") or "")[:10],
            "license": card.get("license"),
            "base_model": card.get("base_model"),
            "datasets": card.get("datasets"),
            "languages": (card.get("language") or [])[:5],
            "tags": _trim_tags(payload.get("tags") or []),
            "file_count": len(files),
            "gguf_files": quants[:40],
            "config": payload.get("config") or {},
            "note": ("`gguf_files` is the practical answer to 'can this run "
                     "here' — a 7B q4 is roughly 4 GB")}


def files(repo_id: str, revision: str = "main") -> dict[str, Any]:
    """File listing with sizes — the quantisation menu."""
    value = (repo_id or "").strip().strip("/")
    if not value:
        return {"ok": False, "err": "files needs a repo id"}
    ok, payload, err = net.get_json(
        f"{BASE}/models/{net.quote(value).replace('%2F', '/')}/tree/{net.quote(revision)}",
        ttl=TTL)
    if not ok or not isinstance(payload, list):
        return {"ok": False, "err": err or "not found", "repo": value}
    rows = []
    for item in payload:
        if item.get("type") != "file":
            continue
        size = item.get("size")
        rows.append({"file": item.get("path"), "bytes": size,
                     "size": _size(size)})
    rows.sort(key=lambda r: r.get("bytes") or 0)
    quant_rows = [r for r in rows if (r["file"] or "").lower().endswith(".gguf")]
    return {"ok": True, "repo": value, "revision": revision,
            "files": rows[:60], "file_count": len(rows),
            "gguf": quant_rows[:40],
            "total_size": _size(sum(r.get("bytes") or 0 for r in rows))}
