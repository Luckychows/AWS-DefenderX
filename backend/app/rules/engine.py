from __future__ import annotations

from typing import Callable, Iterable, List

from ..models import CloudEvent, CloudEventType, Finding, Severity


Rule = Callable[[CloudEvent], List[Finding]]


def run_rules(events: Iterable[CloudEvent]) -> List[Finding]:
    rules: List[Rule] = [
        detect_public_s3_bucket,
        detect_open_ports,
        detect_root_account_usage,
        detect_mfa_disabled,
        detect_overly_permissive_iam,
        detect_cloudtrail_disabled,
        detect_unencrypted_ebs,
    ]
    findings: List[Finding] = []
    for ev in events:
        for rule in rules:
            findings.extend(rule(ev))
    return findings


def detect_public_s3_bucket(ev: CloudEvent) -> List[Finding]:
    if ev.event_type != CloudEventType.s3_bucket_acl:
        return []
    is_public = bool(ev.data.get("public", False))
    if not is_public:
        return []
    return [
        Finding(
            severity=Severity.critical,
            title="Public S3 bucket",
            description=f"S3 bucket `{ev.resource_id}` is publicly accessible.",
            risk="Public buckets frequently lead to data exposure, data exfiltration, or hosting malware.",
            recommendation="Block public access at the bucket + account level and restrict bucket policy to required principals only.",
            account_id=ev.account_id,
            region=ev.region,
            resource_id=ev.resource_id,
            event=ev,
            tags=["s3", "public-access"],
        )
    ]


def detect_open_ports(ev: CloudEvent) -> List[Finding]:
    if ev.event_type != CloudEventType.security_group_rule:
        return []
    cidr = str(ev.data.get("cidr", ""))
    from_port = ev.data.get("from_port")
    to_port = ev.data.get("to_port")
    proto = str(ev.data.get("protocol", "tcp"))
    if cidr != "0.0.0.0/0":
        return []
    if from_port is None or to_port is None:
        return []

    severity = Severity.high
    if int(from_port) <= 22 <= int(to_port) or int(from_port) <= 3389 <= int(to_port):
        severity = Severity.critical

    return [
        Finding(
            severity=severity,
            title="Security group allows open ingress (0.0.0.0/0)",
            description=f"Security group `{ev.resource_id}` allows {proto} {from_port}-{to_port} from 0.0.0.0/0.",
            risk="Open ingress enables Internet-wide scanning and exploitation. Admin ports (SSH/RDP) are a common initial access vector.",
            recommendation="Restrict CIDRs to trusted IP ranges, use SSM Session Manager/bastion, and enforce least-privilege ingress.",
            account_id=ev.account_id,
            region=ev.region,
            resource_id=ev.resource_id,
            event=ev,
            tags=["ec2", "security-group", "ingress"],
        )
    ]


def detect_root_account_usage(ev: CloudEvent) -> List[Finding]:
    if ev.event_type != CloudEventType.root_usage:
        return []
    used = bool(ev.data.get("used", False))
    if not used:
        return []
    return [
        Finding(
            severity=Severity.critical,
            title="Root account usage detected",
            description="An action was performed using the AWS root account.",
            risk="Root usage bypasses normal IAM controls and is difficult to monitor safely. It can indicate compromise or unsafe operational behavior.",
            recommendation="Stop using root. Enable MFA on root, create break-glass procedure, and alert on all root actions.",
            account_id=ev.account_id,
            region=ev.region,
            resource_id="root",
            event=ev,
            tags=["iam", "root"],
        )
    ]


def detect_mfa_disabled(ev: CloudEvent) -> List[Finding]:
    if ev.event_type != CloudEventType.account_mfa:
        return []
    enabled = bool(ev.data.get("enabled", True))
    if enabled:
        return []
    return [
        Finding(
            severity=Severity.high,
            title="MFA disabled",
            description="MFA is disabled for one or more privileged identities.",
            risk="Password-only authentication increases the chance of account takeover via phishing/credential stuffing.",
            recommendation="Require MFA for privileged users, enforce via IAM conditions, and use SSO where possible.",
            account_id=ev.account_id,
            region=ev.region,
            resource_id=ev.resource_id,
            event=ev,
            tags=["iam", "mfa"],
        )
    ]


def detect_overly_permissive_iam(ev: CloudEvent) -> List[Finding]:
    if ev.event_type != CloudEventType.iam_policy:
        return []
    actions = ev.data.get("actions", [])
    resources = ev.data.get("resources", [])
    effect = str(ev.data.get("effect", "Allow"))
    if effect.lower() != "allow":
        return []
    if "*" not in actions and "iam:*" not in actions and "s3:*" not in actions:
        return []
    if "*" not in resources:
        return []
    return [
        Finding(
            severity=Severity.high,
            title="Overly permissive IAM policy",
            description=f"Policy on `{ev.resource_id}` contains wildcard allow permissions (actions={actions}, resources={resources}).",
            risk="Wildcard permissions enable lateral movement and privilege escalation after a single credential compromise.",
            recommendation="Scope actions/resources to least privilege, add conditions, and use access analyzer to validate.",
            account_id=ev.account_id,
            region=ev.region,
            resource_id=ev.resource_id,
            event=ev,
            tags=["iam", "policy", "least-privilege"],
        )
    ]


def detect_cloudtrail_disabled(ev: CloudEvent) -> List[Finding]:
    if ev.event_type != CloudEventType.cloudtrail_status:
        return []
    enabled = bool(ev.data.get("enabled", True))
    if enabled:
        return []
    return [
        Finding(
            severity=Severity.high,
            title="CloudTrail disabled",
            description="CloudTrail is disabled or not configured for this account/region.",
            risk="Without CloudTrail, incident response and forensics are severely limited and attacker activity may go undetected.",
            recommendation="Enable org-wide CloudTrail, send to a central immutable log bucket, and enable log file validation.",
            account_id=ev.account_id,
            region=ev.region,
            resource_id="cloudtrail",
            event=ev,
            tags=["cloudtrail", "logging"],
        )
    ]


def detect_unencrypted_ebs(ev: CloudEvent) -> List[Finding]:
    if ev.event_type != CloudEventType.ebs_volume:
        return []
    encrypted = bool(ev.data.get("encrypted", True))
    if encrypted:
        return []
    return [
        Finding(
            severity=Severity.medium,
            title="Unencrypted EBS volume",
            description=f"EBS volume `{ev.resource_id}` is not encrypted at rest.",
            risk="Unencrypted storage increases data exposure risk if snapshots/volumes are accessed improperly.",
            recommendation="Enable default EBS encryption and migrate volumes to encrypted copies using snapshots.",
            account_id=ev.account_id,
            region=ev.region,
            resource_id=ev.resource_id,
            event=ev,
            tags=["ebs", "encryption"],
        )
    ]

