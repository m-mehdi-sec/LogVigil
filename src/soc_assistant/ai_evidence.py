"""Reject selected unsupported claims in AI-generated SOC analysis."""

import re


DOCUMENTATION_IP = re.compile(
    r"\b(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}\b"
)

SIMULATION_CLAIM = re.compile(
    r"\b(?:indicat(?:e|es|ing)|prov(?:e|es|ing)|confirm(?:s|ed|ing)?|"
    r"demonstrat(?:e|es|ing)|evidence of|given|due to|because|"
    r"simulation)\b",
    re.IGNORECASE,
)

INTENTIONAL_COMPROMISE_CLAIM = re.compile(
    r"\b(?:account|user|credentials?)\b.{0,100}"
    r"\b(?:intentionally|deliberately|purposely)\s+compromised\b",
    re.IGNORECASE,
)


def validate_ai_evidence(analysis, context):
    """Reject narrowly defined claims unsupported by supplied evidence."""
    if not isinstance(analysis, dict) or not isinstance(context, dict):
        raise ValueError("Invalid AI evidence validation input")

    for field in ("observations", "hypotheses", "recommended_actions"):
        items = analysis.get(field)

        if not isinstance(items, list):
            raise ValueError("Invalid AI evidence field")

        for item in items:
            if not isinstance(item, str):
                raise ValueError("Invalid AI evidence item")

            if field in ("observations", "hypotheses"):
                if (
                    DOCUMENTATION_IP.search(item)
                    and SIMULATION_CLAIM.search(item)
                ):
                    raise ValueError(
                        "AI analysis uses documentation IP as simulation evidence"
                    )

            if INTENTIONAL_COMPROMISE_CLAIM.search(item):
                raise ValueError(
                    "AI analysis contains unsupported account compromise claim"
                )

    return analysis
