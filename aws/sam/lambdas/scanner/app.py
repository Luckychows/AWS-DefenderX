from __future__ import annotations

import os
import json
from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import uuid4
from urllib import request

import boto3


TABLE_NAME = os.environ["FINDINGS_TABLE"]
dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(TABLE_NAME)
ENABLE_SECURITY_INTEGRATIONS = os.environ.get("ENABLE_SECURITY_INTEGRATIONS", "false").lower() == "true"

ec2 = boto3.client("ec2")
s3 = boto3.client("s3")
iam = boto3.client("iam")
cloudtrail = boto3.client("cloudtrail")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _put_finding(f: Dict[str, Any]) -> None:
    item = {
        "pk": f"FINDING#{f['finding_id']}",
        "sk": "METADATA",
        "gsi1pk": "FINDINGS",
        "gsi1sk": f"{f['created_at']}#{f['severity']}",
        **f,
    }
    table.put_item(Item=item)
    _emit_integrations(f)


def _post_json(url: str, payload: Dict[str, Any], headers: Dict[str, str] | None = None) -> None:
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
        "source": "aws-periodic-scanner",
        "finding": finding,
    }

    splunk_url = os.environ.get("SPLUNK_HEC_URL", "")
    splunk_token = os.environ.get("SPLUNK_HEC_TOKEN", "")
    if splunk_url and splunk_token:
        body = {"event": base_event, "sourcetype": "_json", "index": os.environ.get("SPLUNK_HEC_INDEX", "main")}
        _post_json(splunk_url, body, {"Authorization": f"Splunk {splunk_token}"})

    elastic_url = os.environ.get("ELASTIC_URL", "").rstrip("/")
    if elastic_url:
        elastic_index = os.environ.get("ELASTIC_INDEX", "cloud-misconfig-findings")
        elastic_api_key = os.environ.get("ELASTIC_API_KEY", "")
        headers = {"Authorization": f"ApiKey {elastic_api_key}"} if elastic_api_key else {}
        _post_json(f"{elastic_url}/{elastic_index}/_doc", {"@timestamp": _now(), **base_event}, headers)

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
    tags: List[str],
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
        "tags": tags,
    }


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Periodic scanner: runs on a schedule and evaluates current account posture.
    This catches "state" issues without requiring any manual log uploads.
    """
    sts = boto3.client("sts")
    identity = sts.get_caller_identity()
    account_id = identity.get("Account", "000000000000")
    region = os.environ.get("AWS_REGION", "us-east-1")

    findings: List[Dict[str, Any]] = []

    # 1) Public S3 buckets (best-effort signals)
    buckets = s3.list_buckets().get("Buckets", [])
    for b in buckets:
        name = b["Name"]
        public = False
        reasons: List[str] = []

        try:
            pab = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
            if not (pab.get("BlockPublicAcls") and pab.get("IgnorePublicAcls") and pab.get("BlockPublicPolicy") and pab.get("RestrictPublicBuckets")):
                reasons.append("PublicAccessBlock not fully enabled")
        except Exception:
            reasons.append("PublicAccessBlock missing or inaccessible")

        try:
            status = s3.get_bucket_policy_status(Bucket=name).get("PolicyStatus", {})
            if status.get("IsPublic") is True:
                public = True
                reasons.append("Bucket policy status indicates public")
        except Exception:
            pass

        if public or reasons:
            if public:
                findings.append(
                    _finding(
                        severity="critical",
                        title="Public S3 bucket",
                        description=f"S3 bucket `{name}` appears publicly accessible ({', '.join(reasons) or 'policy status'}).",
                        risk="Public buckets frequently lead to data exposure, data exfiltration, or hosting malware.",
                        recommendation="Enable Block Public Access and restrict bucket policies to required principals only.",
                        account_id=account_id,
                        region=region,
                        resource_id=name,
                        event={"scanner": "s3", "bucket": name, "reasons": reasons},
                        tags=["s3", "public-access"],
                    )
                )

    # 2) Open security groups (0.0.0.0/0)
    sgs = ec2.describe_security_groups().get("SecurityGroups", [])
    for sg in sgs:
        sg_id = sg.get("GroupId", "unknown")
        for perm in sg.get("IpPermissions", []):
            ip_ranges = perm.get("IpRanges", [])
            for r in ip_ranges:
                if r.get("CidrIp") == "0.0.0.0/0":
                    from_p = perm.get("FromPort")
                    to_p = perm.get("ToPort")
                    proto = perm.get("IpProtocol")
                    sev = "high"
                    if from_p is not None and to_p is not None and (from_p <= 22 <= to_p or from_p <= 3389 <= to_p):
                        sev = "critical"
                    findings.append(
                        _finding(
                            severity=sev,
                            title="Security group allows open ingress (0.0.0.0/0)",
                            description=f"Security group `{sg_id}` allows {proto} {from_p}-{to_p} from 0.0.0.0/0.",
                            risk="Open ingress enables Internet-wide scanning and exploitation. Admin ports are common initial access.",
                            recommendation="Restrict CIDRs to trusted ranges; prefer SSM Session Manager; enforce guardrails.",
                            account_id=account_id,
                            region=region,
                            resource_id=sg_id,
                            event={"scanner": "ec2", "security_group": sg_id, "permission": perm},
                            tags=["ec2", "security-group", "ingress"],
                        )
                    )

    # 3) CloudTrail disabled (no active trails logging)
    trails = cloudtrail.describe_trails(includeShadowTrails=False).get("trailList", [])
    any_logging = False
    for t in trails:
        arn = t.get("TrailARN")
        if not arn:
            continue
        try:
            st = cloudtrail.get_trail_status(Name=arn)
            if st.get("IsLogging") is True:
                any_logging = True
        except Exception:
            continue
    if not any_logging:
        findings.append(
            _finding(
                severity="high",
                title="CloudTrail disabled",
                description="No CloudTrail trails appear to be actively logging.",
                risk="Without CloudTrail, forensics and detection coverage drop significantly.",
                recommendation="Enable org-wide CloudTrail, centralize logs, enable log validation.",
                account_id=account_id,
                region=region,
                resource_id="cloudtrail",
                event={"scanner": "cloudtrail", "trail_count": len(trails)},
                tags=["cloudtrail", "logging"],
            )
        )

    # 4) Unencrypted EBS volumes
    vols = ec2.describe_volumes().get("Volumes", [])
    for v in vols:
        if v.get("Encrypted") is False:
            vid = v.get("VolumeId", "unknown")
            findings.append(
                _finding(
                    severity="medium",
                    title="Unencrypted EBS volume",
                    description=f"EBS volume `{vid}` is not encrypted at rest.",
                    risk="Unencrypted storage increases exposure if snapshots/volumes are accessed improperly.",
                    recommendation="Enable default EBS encryption and migrate volumes to encrypted copies.",
                    account_id=account_id,
                    region=region,
                    resource_id=vid,
                    event={"scanner": "ebs", "volume": v},
                    tags=["ebs", "encryption"],
                )
            )

    # 5) Root / MFA posture (high-level)
    try:
        summary = iam.get_account_summary().get("SummaryMap", {})
        mfa_enabled = summary.get("AccountMFAEnabled", 0) == 1
        if not mfa_enabled:
            findings.append(
                _finding(
                    severity="high",
                    title="MFA disabled (account)",
                    description="Account-level MFA appears disabled (AccountMFAEnabled=0).",
                    risk="Password-only access increases risk of takeover.",
                    recommendation="Enable MFA for root and require MFA for privileged identities.",
                    account_id=account_id,
                    region=region,
                    resource_id="account",
                    event={"scanner": "iam", "summary": summary},
                    tags=["iam", "mfa"],
                )
            )
    except Exception:
        pass

    for f in findings:
        _put_finding(f)

    return {"ok": True, "findings_created": len(findings)}

