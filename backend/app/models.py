from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class FindingStatus(str, Enum):
    open = "open"
    remediated = "remediated"
    suppressed = "suppressed"


class CloudEventType(str, Enum):
    s3_bucket_acl = "s3_bucket_acl"
    security_group_rule = "security_group_rule"
    iam_policy = "iam_policy"
    account_mfa = "account_mfa"
    cloudtrail_status = "cloudtrail_status"
    ebs_volume = "ebs_volume"
    root_usage = "root_usage"


class CloudEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    event_type: CloudEventType
    account_id: str = "000000000000"
    region: str = "us-east-1"
    resource_id: str
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    data: Dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    status: FindingStatus = FindingStatus.open
    severity: Severity
    title: str
    description: str
    risk: str
    recommendation: str

    account_id: str
    region: str
    resource_id: str

    event: CloudEvent
    ai_summary: Optional[str] = None
    tags: List[str] = Field(default_factory=list)


class RemediationAction(BaseModel):
    action_id: str = Field(default_factory=lambda: str(uuid4()))
    finding_id: str
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    actor: str = "local-user"
    status: str = "recorded"
    details: Dict[str, Any] = Field(default_factory=dict)


class IngestRequest(BaseModel):
    events: List[CloudEvent]


class IngestResponse(BaseModel):
    findings_created: int
    finding_ids: List[str]

