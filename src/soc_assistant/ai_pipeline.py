"""Orchestrate bounded local AI analysis of SOC reports."""

from soc_assistant.ai_analyzer import build_ai_request
from soc_assistant.ai_context import build_ai_context
from soc_assistant.ollama_client import analyze_with_ollama
from soc_assistant.ai_safety import sanitize_ai_analysis


def analyze_soc_report(
    report,
    *,
    model="qwen2.5:7b",
    timeout=30,
    max_groups=5,
    max_findings=20,
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
    )

    request = build_ai_request(context)

    result = analyze_with_ollama(
        request,
        model=model,
        timeout=timeout,
    )

    return {
        "application": "LogVigil",
        "analysis_version": "1.0",
        "model": model,
        "context_summary": {
            "investigations_sent": len(context["investigations"]),
            "findings_sent": sum(
                len(group["findings"])
                for group in context["investigations"]
            ),
        },
        "ai_analysis": sanitize_ai_analysis(result),
    }
