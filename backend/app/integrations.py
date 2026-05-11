from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Protocol

import httpx

from .models import Finding
from .settings import Settings


class AlertSink(Protocol):
    async def send(self, finding: Finding) -> None: ...


@dataclass(frozen=True)
class JsonlSink:
    path: Path

    async def send(self, finding: Finding) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": "cloud_misconfig_finding",
            "finding": finding.model_dump(mode="json"),
        }
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload) + "\n")


@dataclass(frozen=True)
class SplunkHecSink:
    url: str
    token: str
    index: str | None
    sourcetype: str

    async def send(self, finding: Finding) -> None:
        # HEC format: {"event":{...}, "sourcetype":"...", "index":"..."}
        body: Dict[str, Any] = {
            "time": datetime.now(timezone.utc).timestamp(),
            "sourcetype": self.sourcetype,
            "event": {
                "type": "cloud_misconfig_finding",
                "finding": finding.model_dump(mode="json"),
            },
        }
        if self.index:
            body["index"] = self.index

        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(
                self.url,
                headers={"Authorization": f"Splunk {self.token}"},
                json=body,
            )
            r.raise_for_status()


@dataclass(frozen=True)
class ElasticSink:
    base_url: str
    api_key: str | None
    index: str

    async def send(self, finding: Finding) -> None:
        # Simple indexing call: POST /{index}/_doc
        doc = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "cloud_misconfig_finding",
            "finding": finding.model_dump(mode="json"),
        }
        url = self.base_url.rstrip("/") + f"/{self.index}/_doc"
        headers: Dict[str, str] = {}
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(
                url,
                headers=headers or None,
                json=doc,
            )
            r.raise_for_status()


def build_sinks(settings: Settings) -> List[AlertSink]:
    sinks: List[AlertSink] = []
    enabled = [s.strip().lower() for s in settings.alert_sinks.split(",") if s.strip()]

    if "jsonl" in enabled:
        sinks.append(JsonlSink(path=Path(settings.alerts_jsonl_path)))

    if "splunk" in enabled and settings.splunk_hec_url and settings.splunk_hec_token:
        sinks.append(
            SplunkHecSink(
                url=settings.splunk_hec_url,
                token=settings.splunk_hec_token,
                index=settings.splunk_hec_index,
                sourcetype=settings.splunk_hec_sourcetype,
            )
        )

    if "elastic" in enabled and settings.elastic_url:
        sinks.append(
            ElasticSink(
                base_url=settings.elastic_url,
                api_key=settings.elastic_api_key,
                index=settings.elastic_index,
            )
        )

    return sinks


async def emit_findings(sinks: Iterable[AlertSink], findings: Iterable[Finding]) -> None:
    # Best-effort: one sink failure should not break ingest for local MVP.
    for f in findings:
        for s in sinks:
            try:
                await s.send(f)
            except Exception:
                continue

