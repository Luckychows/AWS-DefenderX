from __future__ import annotations

import json
import os
from decimal import Decimal
from datetime import datetime
from typing import Any, Dict, List, Optional

import boto3
import httpx
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from mangum import Mangum


FINDINGS_TABLE = os.environ["FINDINGS_TABLE"]
OPENAI_SECRET_NAME = os.environ.get("OPENAI_SECRET_NAME")
API_AUTH_TOKEN = os.environ.get("API_AUTH_TOKEN", "")
ENABLE_AUTO_REMEDIATION = os.environ.get("ENABLE_AUTO_REMEDIATION", "false").lower() == "true"

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(FINDINGS_TABLE)
secrets = boto3.client("secretsmanager")
s3 = boto3.client("s3")
ec2 = boto3.client("ec2")
cloudtrail = boto3.client("cloudtrail")

app = FastAPI(title="Cloud Misconfig API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
handler = Mangum(app)


def _json_safe(value: Any) -> Any:
    if isinstance(value, Decimal):
        # Convert Decimal from DynamoDB into JSON-safe number/string.
        if value % 1 == 0:
            return int(value)
        return float(value)
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    return value


def _assert_auth(x_api_token: Optional[str]) -> None:
    if not API_AUTH_TOKEN or API_AUTH_TOKEN == "change-me":
        raise HTTPException(status_code=500, detail="API auth token not configured")
    if x_api_token != API_AUTH_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")


def _get_openai_key() -> Optional[str]:
    if not OPENAI_SECRET_NAME:
        return None
    try:
        v = secrets.get_secret_value(SecretId=OPENAI_SECRET_NAME)
        raw = v.get("SecretString") or ""
        data = json.loads(raw) if raw.strip().startswith("{") else {"OPENAI_API_KEY": raw}
        return data.get("OPENAI_API_KEY")
    except Exception:
        return None


@app.get("/findings")
def list_findings(limit: int = 200, x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _assert_auth(x_api_token)
    # Read via GSI newest-first by created_at (string sort works for ISO timestamps)
    resp = table.query(
        IndexName="gsi1",
        KeyConditionExpression="gsi1pk = :pk",
        ExpressionAttributeValues={":pk": "FINDINGS"},
        ScanIndexForward=False,
        Limit=min(max(limit, 1), 1000),
    )
    items = resp.get("Items", [])
    for it in items:
        it.pop("pk", None)
        it.pop("sk", None)
        it.pop("gsi1pk", None)
        it.pop("gsi1sk", None)
    return {"findings": items}


@app.get("/findings/{finding_id}")
def get_finding(finding_id: str, x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _assert_auth(x_api_token)
    resp = table.get_item(Key={"pk": f"FINDING#{finding_id}", "sk": "METADATA"})
    it = resp.get("Item")
    if not it:
        raise HTTPException(status_code=404, detail="Not found")
    it.pop("pk", None)
    it.pop("sk", None)
    it.pop("gsi1pk", None)
    it.pop("gsi1sk", None)
    return {"finding": it}


@app.post("/findings/{finding_id}/summarize")
async def summarize_finding(finding_id: str, x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _assert_auth(x_api_token)
    resp = table.get_item(Key={"pk": f"FINDING#{finding_id}", "sk": "METADATA"})
    it = resp.get("Item")
    if not it:
        raise HTTPException(status_code=404, detail="Not found")

    key = _get_openai_key()
    if not key:
        raise HTTPException(status_code=400, detail="OpenAI key not configured")

    prompt = (
        "You are a cloud security analyst. Summarize the risk in 5-8 bullet points, "
        "then provide a short remediation plan with 3 concrete steps.\\n\\n"
        f"Finding: {it.get('title')}\\n"
        f"Severity: {it.get('severity')}\\n"
        f"Description: {it.get('description')}\\n"
        f"Risk: {it.get('risk')}\\n"
        f"Recommendation: {it.get('recommendation')}\\n"
        f"Resource: {it.get('resource_id')} Region: {it.get('region')} Account: {it.get('account_id')}\\n"
        f"Event: {json.dumps(_json_safe(it.get('event', {})))}\\n"
    )

    async with httpx.AsyncClient(timeout=20.0) as client:
        r = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json={
                "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                "messages": [
                    {"role": "system", "content": "You help security teams triage cloud findings."},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.2,
            },
        )
        r.raise_for_status()
        data = r.json()
        summary = data["choices"][0]["message"]["content"]

    table.update_item(
        Key={"pk": f"FINDING#{finding_id}", "sk": "METADATA"},
        UpdateExpression="SET ai_summary=:s, updated_at=:u",
        ExpressionAttributeValues={":s": summary, ":u": datetime.utcnow().isoformat()},
    )
    return {"finding_id": finding_id, "ai_summary": summary}


def _record_remediation(finding_id: str, details: Dict[str, Any], status: str = "remediated") -> None:
    action_id = f"remed-{finding_id}-{int(datetime.utcnow().timestamp())}"
    table.put_item(
        Item={
            "pk": f"FINDING#{finding_id}",
            "sk": f"REMEDIATION#{action_id}",
            "action_id": action_id,
            "finding_id": finding_id,
            "executed_at": datetime.utcnow().isoformat(),
            "actor": "aws-api-lambda",
            "status": status,
            "details": details,
        }
    )
    table.update_item(
        Key={"pk": f"FINDING#{finding_id}", "sk": "METADATA"},
        UpdateExpression="SET #s=:s, updated_at=:u",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": status, ":u": datetime.utcnow().isoformat()},
    )


def _extract_open_ingress_permissions(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    perm = event.get("permission")
    if isinstance(perm, dict):
        out.append(perm)
    return out


@app.post("/findings/{finding_id}/remediate")
def remediate_finding(finding_id: str, x_api_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _assert_auth(x_api_token)
    if not ENABLE_AUTO_REMEDIATION:
        raise HTTPException(status_code=400, detail="Auto-remediation disabled")

    resp = table.get_item(Key={"pk": f"FINDING#{finding_id}", "sk": "METADATA"})
    finding = resp.get("Item")
    if not finding:
        raise HTTPException(status_code=404, detail="Not found")

    title = (finding.get("title") or "").lower()
    resource_id = finding.get("resource_id") or ""
    event = finding.get("event") or {}
    remediation_details: Dict[str, Any] = {"finding_id": finding_id, "title": finding.get("title")}

    try:
        if "public s3 bucket" in title and resource_id:
            s3.put_public_access_block(
                Bucket=resource_id,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )
            remediation_details["action"] = "Applied S3 Block Public Access"
        elif "security group allows open ingress" in title and resource_id:
            perms = _extract_open_ingress_permissions(event)
            if perms:
                ec2.revoke_security_group_ingress(GroupId=resource_id, IpPermissions=perms)
                remediation_details["action"] = "Revoked open ingress permission"
            else:
                remediation_details["action"] = "No permission payload available; manual review required"
                _record_remediation(finding_id, remediation_details, status="suppressed")
                return {"ok": True, "status": "suppressed", "details": remediation_details}
        elif "cloudtrail disabled" in title:
            trails = cloudtrail.describe_trails(includeShadowTrails=False).get("trailList", [])
            started = 0
            for t in trails:
                name = t.get("Name")
                if not name:
                    continue
                try:
                    cloudtrail.start_logging(Name=name)
                    started += 1
                except Exception:
                    continue
            remediation_details["action"] = f"Attempted to start CloudTrail logging on {started} trails"
        else:
            remediation_details["action"] = "No safe automatic remediation mapped for this finding type"
            _record_remediation(finding_id, remediation_details, status="suppressed")
            return {"ok": True, "status": "suppressed", "details": remediation_details}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Remediation failed: {exc}")

    _record_remediation(finding_id, remediation_details, status="remediated")
    return {"ok": True, "status": "remediated", "details": remediation_details}

