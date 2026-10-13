"""Enforce advisory-only handling of AI analysis results."""

import copy

ALLOWED_RISK_LEVELS = {
    "critical", "high", "medium", "low", "informational"
}

MAX_ITEMS_PER_FIELD = 20
MAX_ITEM_LENGTH = 1000

ADVISORY_NOTICE = (
    "AI-generated recommendations are advisory only. "
    "Human review is required before taking action."
)


def sanitize_ai_analysis(analysis):
    """Return validated, bounded, advisory-only AI findings."""
    if not isinstance(analysis, dict):
        raise ValueError("AI analysis must be an object")

    allowed = {
        "risk_level",
        "observations",
        "hypotheses",
        "recommended_actions",
    }

    if set(analysis) != allowed:
        raise ValueError("Unexpected AI analysis fields")

    risk = analysis["risk_level"]

    if not isinstance(risk, str) or risk not in ALLOWED_RISK_LEVELS:
        raise ValueError("Invalid AI risk level")

    result = {"risk_level": risk}

    for field in (
        "observations",
        "hypotheses",
        "recommended_actions",
    ):
        items = analysis[field]

        if not isinstance(items, list):
            raise ValueError("AI analysis field must be a list")

        if len(items) > MAX_ITEMS_PER_FIELD:
            raise ValueError("Too many AI analysis items")

        cleaned = []

        for item in items:
            if not isinstance(item, str):
                raise ValueError("AI analysis item must be text")

            if not item.strip():
                raise ValueError("AI analysis item cannot be empty")

            if len(item) > MAX_ITEM_LENGTH:
                raise ValueError("AI analysis item exceeds size limit")

            cleaned.append(item.strip())

        result[field] = cleaned

    result["execution_authorized"] = False
    result["requires_human_review"] = True
    result["advisory_notice"] = ADVISORY_NOTICE

    return copy.deepcopy(result)
