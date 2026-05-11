from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4
from urllib import request

import boto3


TABLE_NAME = os.environ["FINDINGS_TABLE"]
dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(TABLE_NAME)
ENABLE_SECURITY_INTEGRATIONS = os.environ.get("ENABLE_SECURITY_INTEGRATIONS", "false").lower() == "true"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _put_finding(f: Dict[str, Any]) -> None:
    # Single-table style:
    # pk = FINDING#{id}, sk = METADATA
    # gsi1pk = FINDINGS, gsi1sk = created_at#severity
    item = {
        "pk": f"FINDING#{f['finding_id']}",
        "sk": "METADATA",
        "gsi1pk": "FINDINGS",
        "gsi1sk": f"{f['created_at']}#{f['severity']}",
        **f,
    }
    table.put_item(Item=item)
    _emit_integrations(f)


def _post_json(url: str, payload: Dict[str, Any], headers: Optional[Dict[str, str]] = None) -> None:
    if not url:
        return
    req = request.Request(
        url=url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    with request.urlopen(req, timeout=8):
        pass


def _emit_integrations(finding: Dict[str, Any]) -> None:
    if not ENABLE_SECURITY_INTEGRATIONS:
        return

    base_event = {
        "type": "cloud_misconfig_finding",
        "source": "aws-realtime-detector",
        "finding": finding,
    }

    # Splunk HEC
    splunk_url = os.environ.get("SPLUNK_HEC_URL", "")
    splunk_token = os.environ.get("SPLUNK_HEC_TOKEN", "")
    if splunk_url and splunk_token:
        body = {"event": base_event, "sourcetype": "_json", "index": os.environ.get("SPLUNK_HEC_INDEX", "main")}
        _post_json(splunk_url, body, {"Authorization": f"Splunk {splunk_token}"})

    # Elastic
    elastic_url = os.environ.get("ELASTIC_URL", "").rstrip("/")
    if elastic_url:
        elastic_index = os.environ.get("ELASTIC_INDEX", "cloud-misconfig-findings")
        elastic_api_key = os.environ.get("ELASTIC_API_KEY", "")
        headers = {"Authorization": f"ApiKey {elastic_api_key}"} if elastic_api_key else {}
        _post_json(f"{elastic_url}/{elastic_index}/_doc", {"@timestamp": _now(), **base_event}, headers)

    # Wazuh / Suricata / Falco generic webhook fanout
    for name, url_env, key_env in [
        ("wazuh", "WAZUH_WEBHOOK_URL", "WAZUH_API_KEY"),
        ("suricata", "SURICATA_WEBHOOK_URL", "SURICATA_API_KEY"),
        ("falco", "FALCO_WEBHOOK_URL", "FALCO_API_KEY"),
    ]:
        url = os.environ.get(url_env, "")
        api_key = os.environ.get(key_env, "")
        if not url:
            continue
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        _post_json(url, {**base_event, "target": name}, headers)


def _finding(
    *,
    severity: str,
    title: str,
    description: str,
    risk: str,
    recommendation: str,
    account_id: str,
    region: str,
    resource_id: str,
    event: Dict[str, Any],
    tags: Optional[List[str]] = None,
) -> Dict[str, Any]:
    fid = str(uuid4())
    ts = _now()
    return {
        "finding_id": fid,
        "created_at": ts,
        "updated_at": ts,
        "status": "open",
        "severity": severity,
        "title": title,
        "description": description,
        "risk": risk,
        "recommendation": recommendation,
        "account_id": account_id,
        "region": region,
        "resource_id": resource_id,
        "event": event,
        "ai_summary": None,
        "tags": tags or [],
    }


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Realtime detector: receives EventBridge events (CloudTrail-sourced) and creates findings
    for high-signal issues like root usage / SG open ingress / CloudTrail stop attempts.
    """
    findings: List[Dict[str, Any]] = []

    source = event.get("source", "")
    region = event.get("region") or "us-east-1"
    account_id = event.get("account") or "000000000000"
    detail = event.get("detail") or {}
    detail_type = event.get("detail-type") or ""

    # Root console login (or root identity usage in signin events)
    if source == "aws.signin" and "Sign In" in detail_type:
        uid = (detail.get("userIdentity") or {}).get("type")
        if uid == "Root":
            findings.append(
                _finding(
                    severity="critical",
                    title="Root account usage detected",
                    description="AWS root user activity detected from CloudTrail sign-in event.",
                    risk="Root usage bypasses normal IAM controls and can indicate compromise or unsafe operations.",
                    recommendation="Enable MFA on root, restrict root usage to break-glass, and alert on all root actions.",
                    account_id=account_id,
                    region=region,
                    resource_id="root",
                    event=event,
                    tags=["iam", "root", "cloudtrail"],
                )
            )

    # Security group ingress changes (we can't infer CIDRs reliably from all shapes here;
    # periodic scanner will do full state evaluation. This realtime finding is a breadcrumb.)
    if source == "aws.ec2" and detail.get("eventName") == "AuthorizeSecurityGroupIngress":
        sg_id = ((detail.get("requestParameters") or {}).get("groupId")) or "unknown-sg"
        findings.append(
            _finding(
                severity="medium",
                title="Security group ingress modified",
                description=f"Security group `{sg_id}` had ingress rules changed (AuthorizeSecurityGroupIngress).",
                risk="Ingress changes are a common precursor to opening admin ports or exposing services.",
                recommendation="Review the new ingress rules for 0.0.0.0/0 exposure and enforce guardrails.",
                account_id=account_id,
                region=region,
                resource_id=sg_id,
                event=event,
                tags=["ec2", "security-group", "change"],
            )
        )

    # CloudTrail stop/delete attempts
    if source == "aws.cloudtrail" and detail.get("eventName") in {"StopLogging", "DeleteTrail"}:
        findings.append(
            _finding(
                severity="high",
                title="CloudTrail logging tampering detected",
                description=f"CloudTrail API `{detail.get('eventName')}` was called.",
                risk="Disabling CloudTrail reduces visibility and is commonly used by attackers to cover tracks.",
                recommendation="Investigate actor, re-enable org trail, and restrict CloudTrail write permissions.",
                account_id=account_id,
                region=region,
                resource_id="cloudtrail",
                event=event,
                tags=["cloudtrail", "logging", "tamper"],
            )
        )

    # Persist
    for f in findings:
        _put_finding(f)

    return {
        "ok": True,
        "findings_created": len(findings),
        "finding_ids": [f["finding_id"] for f in findings],
    }

