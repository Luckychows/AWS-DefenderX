from __future__ import annotations

import os
from typing import Optional

import httpx

from .models import Finding


class RiskSummarizer:
    def __init__(self) -> None:
        self._openai_key = os.getenv("OPENAI_API_KEY")
        self._openai_model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    async def summarize(self, finding: Finding) -> str:
        if not self._openai_key:
            return self._offline_summary(finding)
        try:
            s = await self._openai_summary(finding)
            return s or self._offline_summary(finding)
        except Exception:
            return self._offline_summary(finding)

    def _offline_summary(self, finding: Finding) -> str:
        return (
            f"Risk: {finding.title} ({finding.severity}).\\n"
            f"Impact: {finding.risk}\\n"
            f"Why it matters: This condition is commonly exploited during initial access and lateral movement.\\n"
            f"Suggested fix: {finding.recommendation}\\n"
            f"Resource: {finding.resource_id} in {finding.region} (acct {finding.account_id})."
        )

    async def _openai_summary(self, finding: Finding) -> Optional[str]:
        prompt = (
            "You are a cloud security analyst. Summarize the risk in 5-8 bullet points, "
            "then provide a short remediation plan with 3 concrete steps. "
            "Keep it actionable and avoid vendor fluff.\\n\\n"
            f"Finding title: {finding.title}\\n"
            f"Severity: {finding.severity}\\n"
            f"Description: {finding.description}\\n"
            f"Risk: {finding.risk}\\n"
            f"Recommendation: {finding.recommendation}\\n"
            f"Account: {finding.account_id} Region: {finding.region} Resource: {finding.resource_id}\\n"
            f"Event data: {finding.event.data}\\n"
        )

        # Minimal OpenAI Chat Completions call.
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self._openai_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self._openai_model,
                    "messages": [
                        {"role": "system", "content": "You help security teams triage cloud findings."},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.2,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]

