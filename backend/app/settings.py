from __future__ import annotations

import os
from dataclasses import dataclass


def _env(name: str, default: str | None = None) -> str | None:
    v = os.getenv(name)
    return v if v not in (None, "") else default


@dataclass(frozen=True)
class Settings:
    # AI
    openai_api_key: str | None = _env("OPENAI_API_KEY")
    openai_model: str = _env("OPENAI_MODEL", "gpt-4o-mini") or "gpt-4o-mini"

    # Alert sinks (comma-separated): jsonl,splunk,elastic
    alert_sinks: str = _env("ALERT_SINKS", "jsonl") or "jsonl"

    # JSONL sink
    alerts_jsonl_path: str = _env("ALERTS_JSONL_PATH", "app/data/alerts.jsonl") or "app/data/alerts.jsonl"

    # Splunk HEC sink
    splunk_hec_url: str | None = _env("SPLUNK_HEC_URL")  # e.g. https://splunk:8088/services/collector
    splunk_hec_token: str | None = _env("SPLUNK_HEC_TOKEN")
    splunk_hec_index: str | None = _env("SPLUNK_HEC_INDEX")
    splunk_hec_sourcetype: str = _env("SPLUNK_HEC_SOURCETYPE", "_json") or "_json"

    # Elastic sink (simple index endpoint)
    elastic_url: str | None = _env("ELASTIC_URL")  # e.g. https://elastic:9200
    elastic_api_key: str | None = _env("ELASTIC_API_KEY")  # base64 or raw depending on cluster config
    elastic_index: str = _env("ELASTIC_INDEX", "cloud-misconfig-findings") or "cloud-misconfig-findings"


def load_settings() -> Settings:
    return Settings()

