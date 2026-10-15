"""Orchestrate bounded local AI analysis of SOC reports."""

from soc_assistant.ai_analyzer import build_ai_request
from soc_assistant.ai_context import build_ai_context
from soc_assistant.ollama_client import analyze_with_ollama
from soc_assistant.ai_safety import sanitize_ai_analysis
from soc_assistant.ai_evidence import validate_ai_evidence
from time import monotonic


MAX_EVIDENCE_ATTEMPTS = 2
MIN_RETRY_TIME_SECONDS = 5
EVIDENCE_RETRY_INSTRUCTIONS = (
    "Your previous response was rejected because it contained an "
    "unsupported evidence claim. Regenerate the entire JSON analysis. "
    "Use only the supplied telemetry and simulation_status. "
    "Do not infer simulation from documentation IP addresses. "
    "Do not infer intentional compromise from failed logins. "
    "Keep observations factual, hypotheses uncertain, and "
    "recommended actions investigative."
)


def analyze_soc_report(
    report,
    *,
    model="qwen2.5:7b",
    timeout=30,
    max_groups=5,
    max_findings=20,
    simulation=False,
):
    """Analyze a SOC report using the configured local AI client.

    This function is invoked explicitly; importing it does not
    contact Ollama or modify any system configuration.
    """
    if not isinstance(report, dict):
        raise ValueError("SOC report must be an object")

    if report.get("application") != "LogVigil":
        raise ValueError("Invalid SOC report application")

    if report.get("schema_version") != "1.0":
        raise ValueError("Unsupported SOC report version")

    context = build_ai_context(
        report,
        max_groups=max_groups,
        max_findings=max_findings,
        simulation=simulation,
    )

    request = build_ai_request(context)

    deadline = monotonic() + timeout
    validated = None

    for attempt in range(MAX_EVIDENCE_ATTEMPTS):
        remaining = timeout if attempt == 0 else deadline - monotonic()
        if remaining <= 0 or (
            attempt > 0 and remaining < MIN_RETRY_TIME_SECONDS
        ):
            raise ValueError("AI analysis time budget exhausted")

        current_request = request

        if attempt:
            current_request = {
                **request,
                "system": (
                    request["system"]
                    + " "
                    + EVIDENCE_RETRY_INSTRUCTIONS
                ),
            }

        result = analyze_with_ollama(
            current_request,
            model=model,
            timeout=remaining,
        )
        ai_attempts = attempt + 1

        try:
            validated = validate_ai_evidence(result, context)
        except ValueError:
            if attempt == MAX_EVIDENCE_ATTEMPTS - 1:
                raise
            continue

        break

    verified_evidence = {
        "source": "logvigil_deterministic_analysis",
        "scope": "analyzed_telemetry_only",
        "simulation_status": context["simulation_status"],
        "summary": {
            "events_analyzed": context["summary"]["events_analyzed"],
            "findings_count": context["summary"]["findings_count"],
        },
        "findings": [
            {
                key: finding[key]
                for key in (
                    "finding_id",
                    "rule_id",
                    "severity",
                    "status",
                    "computer",
                    "username",
                    "source_ip",
                    "source_ip_classification",
                    "evidence_record_ids",
                )
                if key in finding
            }
            for group in context["investigations"]
            for finding in group["findings"]
        ],
    }

    return {
        "application": "LogVigil",
        "analysis_version": "1.0",
        "verified_evidence": verified_evidence,
        "ai_attempts": ai_attempts,
        "ai_validation_status": "passed_limited_checks",
        "ai_evidence_notice": (
            "Only verified_evidence is derived from LogVigil's "
            "deterministic analysis. AI-generated statements are "
            "not independently fact-verified and require human review."
        ),
        "simulation_status": context["simulation_status"],
        "model": model,
        "context_summary": {
            "investigations_sent": len(context["investigations"]),
            "findings_sent": sum(
                len(group["findings"])
                for group in context["investigations"]
            ),
        },
        "ai_analysis": sanitize_ai_analysis(validated),
    }
