"""Optional local Ollama analysis over structured, bounded evidence."""

from __future__ import annotations

import json
import logging
from typing import Any

import requests

from config import OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT

logger = logging.getLogger(__name__)
MAX_CONTEXT_CHARS = 12_000


def analyze_scan(scan_result: dict[str, Any]) -> dict[str, Any]:
    """Return advisory AI text or an explicit unavailable status."""
    if not isinstance(scan_result, dict):
        raise TypeError("scan_result must be a dictionary.")
    context = {
        "target_scope": scan_result.get("scope", scan_result.get("target")),
        "status": scan_result.get("status"),
        "services": [
            {
                key: service.get(key)
                for key in (
                    "host", "port", "protocol", "state", "service",
                    "product", "version", "cpe", "evidence", "cve_candidates",
                )
            }
            for service in scan_result.get("services", [])
            if isinstance(service, dict)
        ],
        "findings": scan_result.get("findings", []),
        "risk_assessments": scan_result.get("risk_assessments", []),
        "limitations": scan_result.get("errors", []),
    }
    encoded = json.dumps(context, ensure_ascii=True, default=str)
    while len(encoded) > MAX_CONTEXT_CHARS:
        if context["findings"]:
            context["findings"].pop()
        elif context["services"]:
            context["services"].pop()
        else:
            context = {
                "target_scope": context["target_scope"],
                "status": context["status"],
                "truncated": True,
                "note": "Detailed evidence exceeded the configured prompt limit.",
            }
        encoded = json.dumps(context, ensure_ascii=True, default=str)
    context_text = encoded
    prompt = (
        "You are providing AI-assisted defensive security analysis. "
        "Only interpret the JSON evidence below. Do not invent scan observations, "
        "products, versions, CVE identifiers, CVSS scores, or numeric risk scores. "
        "Treat every CVE as a candidate unless its data explicitly says otherwise. "
        "Separate observed facts, hypotheses, uncertainty, and suggested verification. "
        "Do not provide executable commands. Recommend changes only with a warning "
        "to confirm vendor guidance and operational impact. "
        "Never create or modify risk scores; deterministic scoring is handled separately.\n\n"
        f"Evidence JSON:\n{context_text}"
    )
    try:
        tags_response = requests.get(
            f"{OLLAMA_BASE_URL}/api/tags",
            timeout=min(OLLAMA_TIMEOUT, 10),
        )
        tags_response.raise_for_status()
        tags_payload = tags_response.json()
        if not isinstance(tags_payload, dict):
            raise ValueError("Ollama tags response was not an object.")
        models = tags_payload.get("models", [])
        if not isinstance(models, list):
            raise ValueError("Ollama tags response contained an invalid model list.")
        available = {
            str(item.get("name", ""))
            for item in models
            if isinstance(item, dict)
        }
        if OLLAMA_MODEL not in available:
            return {
                "status": "model_not_found",
                "model": OLLAMA_MODEL,
                "analysis": "AI analysis is unavailable because the configured Ollama model is not installed. No model was downloaded.",
                "error": None,
                "label": "AI-assisted analysis",
            }
        response = requests.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json={
                "model": OLLAMA_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "options": {"num_predict": 700},
            },
            timeout=OLLAMA_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("Ollama analysis response was not an object.")
        message = payload.get("message", {})
        if not isinstance(message, dict):
            raise ValueError("Ollama analysis response contained no message object.")
        text = message.get("content")
        if not isinstance(text, str) or not text.strip():
            raise ValueError("Ollama returned no analysis text.")
        return {
            "status": "completed",
            "model": OLLAMA_MODEL,
            "analysis": text.strip(),
            "error": None,
            "label": "AI-assisted analysis",
        }
    except requests.Timeout as exc:
        logger.warning("Ollama request timed out: %s", exc)
        message = "Ollama analysis timed out; deterministic results are preserved."
    except requests.HTTPError as exc:
        logger.warning("Ollama HTTP error: %s", exc)
        message = "Ollama returned an HTTP error; deterministic results are preserved."
    except (requests.RequestException, ValueError, TypeError, KeyError) as exc:
        logger.warning("Ollama analysis unavailable: %s", exc)
        message = "Ollama is unavailable or returned malformed data; deterministic results are preserved."
    return {
        "status": "unavailable",
        "model": OLLAMA_MODEL,
        "analysis": message,
        "error": message,
        "label": "AI-assisted analysis",
    }


def analyze_with_llm(port: Any, service: str, cves: list[Any]) -> str:
    """Compatibility wrapper for older callers."""
    result = analyze_scan(
        {
            "target": "unspecified",
            "status": "partial",
            "services": [
                {
                    "port": port,
                    "state": "unknown",
                    "service": service,
                    "cve_candidates": cves,
                }
            ],
        }
    )
    return str(result["analysis"])
