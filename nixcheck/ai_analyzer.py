"""
AI-powered diagnostic analysis for nixcheck.

Takes a NixCheckState, serializes it to structured JSON, sends it to an LLM
with a system-administrator expert prompt, and returns a diagnostic report
in natural language with recommendations.
"""

import json
import logging
import os
from typing import Any

from .models import NixCheckState

__all__ = ["analyze_with_ai", "AIAnalyzerError"]

logger = logging.getLogger(__name__)


SYSTEM_PROMPT = """\
You are a senior Linux systems administrator and SRE. You are given the output \
of nixcheck, a deterministic health-check tool that inspects a Linux server.

Your job: analyze the data and produce a concise, actionable diagnostic report.

## Output format

Respond in Markdown with these sections:

### Overall Health
One paragraph: is the system healthy or not? What's the most urgent thing to address?

### Findings
A bullet list. Each finding:
- **[SEVERITY]** Category — what's wrong (or notable), with specific numbers from the data.
  Severity is one of: CRITICAL, HIGH, MEDIUM, LOW, INFO.

### Recommendations
A numbered list of concrete, prioritized actions. Each:
1. What to do — and why (reference the finding).

## Rules
- Be specific: cite actual values (percentages, counts, service names) from the data.
- Don't hallucinate issues not present in the data. If everything is fine, say so.
- Keep it concise. No fluff, no disclaimers, no "please note".
- If the data is incomplete (e.g. permission denied), acknowledge it briefly.
"""


def _serialize_state(state: NixCheckState) -> dict[str, Any]:
    """Serialize the full NixCheckState for the LLM, trimming verbose fields."""
    data = state.model_dump(mode="json")

    # Trim log errors to the most severe ones to keep token count reasonable
    if data.get("log_errors"):
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_errors = sorted(
            data["log_errors"],
            key=lambda e: severity_order.get(
                e.get("severity", "medium") if isinstance(e, dict) else "medium", 5
            ),
        )
        data["log_errors"] = sorted_errors[:50]

    return data


def analyze_with_ai(
    state: NixCheckState,
    model: str = "gpt-4o-mini",
    base_url: str | None = None,
    api_key: str | None = None,
) -> str:
    """Run AI analysis on a NixCheckState and return a Markdown diagnostic.

    Args:
        state: The completed NixCheckState from running the checks.
        model: LLM model name (OpenAI-compatible).
        base_url: Override the API base URL (for Ollama, vLLM, etc.).
                 Falls back to OPENAI_BASE_URL env var, then the client default.
        api_key: API key. Falls back to OPENAI_API_KEY env var.

    Returns:
        Markdown diagnostic report string.

    Raises:
        AIAnalyzerError: If the LLM call fails or the openai package is missing.
    """
    try:
        from openai import OpenAI
    except ImportError:
        raise AIAnalyzerError(
            "The 'openai' package is required for AI analysis. "
            "Install with: pip install -e '.[ai]'"
        )

    # Resolve connection params
    base_url = base_url or os.environ.get("OPENAI_BASE_URL")
    api_key = api_key or os.environ.get("OPENAI_API_KEY", "dummy-key-for-local")

    client = OpenAI(base_url=base_url, api_key=api_key)

    payload = _serialize_state(state)
    user_msg = (
        "Analyze the following nixcheck JSON output and produce a diagnostic report.\n\n"
        "```json\n"
        f"{json.dumps(payload, indent=2, default=str)}\n"
        "```\n"
    )

    logger.info("Calling AI model %s for analysis", model)
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ],
            temperature=0.3,
            max_tokens=2000,
        )
    except Exception as e:
        raise AIAnalyzerError(f"LLM API call failed: {e}") from e

    content = response.choices[0].message.content
    if not content:
        raise AIAnalyzerError("AI returned an empty response")

    return content.strip()


class AIAnalyzerError(Exception):
    """Raised when AI analysis fails."""