"""
web/ai_probe_advisor.py
-----------------------
Raven Phase 8: AI-guided payload selection and response analysis.

Acts as the "brain" of the web scanner.
1. Pre-probe: Selects which payload categories to try based on context.
2. Post-probe: Analyzes responses to confirm exploitability and rule out
   false positives.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Literal, Optional
from pydantic import BaseModel, Field

from core.models import WebVulnType
from providers.base import BaseProvider
from web.fingerprinter import SiteFingerprint

logger = logging.getLogger(__name__)

# ── Dataclasses for AI Analysis ───────────────────────────────────────────────

class ProbeAnalysis(BaseModel):
    """The LLM's conclusion about a specific payload's effect."""
    confirmed: bool
    confidence: Literal["High", "Medium", "Low"]
    explanation: str
    evidence_snippet: str
    remediation: str
    curl_poc: str


# ── AI Advisor Class ──────────────────────────────────────────────────────────

class AIProbeAdvisor:
    """Uses the configured LLM provider to guide the active probe engine."""

    def __init__(self, provider: BaseProvider) -> None:
        self.provider = provider

    def select_payloads_for_target(
        self,
        url: str,
        parameter: str,
        param_context: str,
        fingerprint: SiteFingerprint,
    ) -> list[str]:
        """
        Ask the LLM which vulnerability classes are most likely to be present.
        Returns a list of vuln type names (e.g., ['SQLi', 'XSS']).
        """
        tech_stack = ", ".join(fingerprint.detected_technologies) or "Unknown"
        
        system_prompt = """You are a senior web penetration tester.
Your job is to determine which vulnerability classes are most likely to be present
given a specific injection point and parameter context.

Valid vulnerability classes are:
["SQLi", "XSS", "SSRF", "LFI", "OpenRedirect", "HeaderInjection"]

Rules:
1. Return ONLY a valid JSON array of strings from the list above.
2. Order by likelihood (most likely first).
3. Max 3 items.
4. Explain nothing. No markdown formatting outside the JSON array.
"""

        user_message = f"""Context:
- URL: {url}
- Parameter Name: {parameter}
- Parameter Context: {param_context}
- Tech Stack: {tech_stack}

Which vulnerability classes should we test?
"""
        response_text = self.provider.analyze(system_prompt, user_message)
        
        # Clean up possible markdown code blocks
        response_text = response_text.strip()
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.startswith("```"):
            response_text = response_text[3:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        response_text = response_text.strip()

        try:
            selected = json.loads(response_text)
            if isinstance(selected, list):
                valid_types = {"SQLi", "XSS", "SSRF", "LFI", "OpenRedirect", "HeaderInjection"}
                return [v for v in selected if v in valid_types][:3]
        except json.JSONDecodeError:
            logger.warning(f"AI Advisor returned invalid JSON for payload selection: {response_text}")
            
        # Fallback if LLM fails or returns garbage
        return ["SQLi", "XSS"]

    def analyze_probe_response(
        self,
        url: str,
        parameter: str,
        payload_sent: str,
        vulnerability_type: WebVulnType,
        response_status: int,
        response_headers: dict,
        response_body_snippet: str,
        response_time_ms: float,
        baseline_response_time_ms: float,
    ) -> Optional[ProbeAnalysis]:
        """
        Ask the LLM to determine if the response confirms the vulnerability.
        """
        # We enforce a strict definition of confirmation.
        system_prompt = """You are a senior web penetration tester analyzing a probe response.
Your job is to determine if the response CONFIRMS the vulnerability or is a false positive.

CRITICAL RULES:
1. Be conservative. Only mark confirmed=true if there is unambiguous evidence.
2. For XSS: A literal reflection of the payload is NOT confirmation unless the HTML context allows script execution. Entity-encoded reflections (e.g., &lt;script&gt;) are safe and must be confirmed=false.
3. For SQLi: A descriptive database error message IS confirmation.
4. For Time-based Blind SQLi: If the response time is > 4x the baseline AND > 4000ms, it is confirmed.
5. You MUST respond ONLY as a JSON object matching this schema exactly:
{
  "confirmed": boolean,
  "confidence": "High" | "Medium" | "Low",
  "explanation": "Brief explanation of why it is or isn't confirmed",
  "evidence_snippet": "The exact substring from the response that proves the vulnerability (or empty string)",
  "remediation": "Concrete fix recommendation (if confirmed, else empty)",
  "curl_poc": "A curl command to reproduce (if confirmed, else empty)"
}

Do NOT output any markdown blocks (e.g. ```json), just the raw JSON object.
"""

        # Format headers for the prompt
        headers_str = "\n".join(f"{k}: {v}" for k, v in response_headers.items())
        
        user_message = f"""Probe Details:
- Target URL: {url}
- Parameter: {parameter}
- Vulnerability Type Tested: {vulnerability_type}
- Payload Sent: {payload_sent}

Response Metrics:
- HTTP Status: {response_status}
- Response Time: {response_time_ms:.1f} ms (Baseline: {baseline_response_time_ms:.1f} ms)

Response Headers:
{headers_str}

Response Body Snippet (first 3000 chars):
{response_body_snippet[:3000]}

Analyze the response and return the JSON object.
"""
        response_text = self.provider.analyze(system_prompt, user_message)
        
        # Clean up
        response_text = response_text.strip()
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.startswith("```"):
            response_text = response_text[3:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        response_text = response_text.strip()

        try:
            data = json.loads(response_text)
            return ProbeAnalysis(**data)
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"AI Advisor returned invalid JSON for probe analysis: {e}\nResponse: {response_text}")
            return None
