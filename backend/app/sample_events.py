from __future__ import annotations

from .models import CloudEvent, CloudEventType


def sample_events() -> list[CloudEvent]:
    acct = "123456789012"
    region = "us-east-1"
    return [
        CloudEvent(
            event_type=CloudEventType.s3_bucket_acl,
            account_id=acct,
            region=region,
            resource_id="company-prod-customer-data",
            data={"public": True, "reason": "bucket policy allows s3:GetObject to *"},
        ),
        CloudEvent(
            event_type=CloudEventType.security_group_rule,
            account_id=acct,
            region=region,
            resource_id="sg-0abc123def456",
            data={"cidr": "0.0.0.0/0", "from_port": 22, "to_port": 22, "protocol": "tcp"},
        ),
        CloudEvent(
            event_type=CloudEventType.root_usage,
            account_id=acct,
            region=region,
            resource_id="root",
            data={"used": True, "api": "CreateAccessKey"},
        ),
        CloudEvent(
            event_type=CloudEventType.account_mfa,
            account_id=acct,
            region=region,
            resource_id="arn:aws:iam::123456789012:user/admin",
            data={"enabled": False},
        ),
        CloudEvent(
            event_type=CloudEventType.iam_policy,
            account_id=acct,
            region=region,
            resource_id="arn:aws:iam::123456789012:role/AppServerRole",
            data={"effect": "Allow", "actions": ["*"], "resources": ["*"]},
        ),
        CloudEvent(
            event_type=CloudEventType.cloudtrail_status,
            account_id=acct,
            region=region,
            resource_id="cloudtrail",
            data={"enabled": False},
        ),
        CloudEvent(
            event_type=CloudEventType.ebs_volume,
            account_id=acct,
            region=region,
            resource_id="vol-0123456789abcdef0",
            data={"encrypted": False},
        ),
    ]

