import argparse
import json
from pathlib import Path

from soc_assistant.parser import parse_jsonl
from soc_assistant.normalizer import normalize_events
from soc_assistant.validator import validate_events
from soc_assistant.detector import (
    detect_brute_force,
    detect_success_after_failures,
    detect_account_enumeration,
    detect_account_lockout,
    detect_privileged_group_change,
)
from soc_assistant.models import build_analysis_report
from soc_assistant.ai_context import build_ai_context
from soc_assistant.ai_pipeline import analyze_soc_report
from soc_assistant.ollama_client import OllamaClientError



def format_summary(report):
    """Format a readable SOC investigation summary."""
    summary = report["summary"]

    lines = [
        "LogVigil - SOC Analysis Summary",
        "================================",
        f"Events analyzed: {summary['events_analyzed']}",
        f"Findings: {summary['findings_count']}",
        f"Data quality warnings: {len(report.get('data_quality_warnings', []))}",
        f"Investigation groups: {summary['investigation_groups_count']}",
        f"Highest severity: {(summary['highest_severity'] or 'none').upper()}",
    ]

    for group in report["investigation_groups"]:
        lines.append("")
        severity = (group["highest_severity"] or "none").upper()
        lines.append(
            f"{group['investigation_id']} | {severity} | "
            f"{group['findings_count']} findings"
        )
        lines.append(
            f"  Findings: {', '.join(group['finding_ids'])}"
        )

    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(
        prog="logvigil",
        description="LogVigil - Local SOC Log Analyzer"
    )
    parser.add_argument(
        "log_file",
        help="Path to a JSONL log file"
    )

    parser.add_argument(
        "--output",
        help="Save detection results to a JSON file"
    )

    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate a structured SOC analysis report"
    )

    parser.add_argument(
        "--summary",
        action="store_true",
        help="Display a readable SOC investigation summary"
    )

    parser.add_argument(
        "--ai-context",
        action="store_true",
        help="Generate bounded JSON context for local AI analysis"
    )
    parser.add_argument(
        "--max-groups",
        type=int,
        default=5,
        help="Maximum AI investigation groups (default: 5)"
    )
    parser.add_argument(
        "--max-findings",
        type=int,
        default=20,
        help="Maximum AI findings (default: 20)"
    )

    parser.add_argument(
        "--analyze-ai",
        action="store_true",
        help="Explicitly run local Ollama SOC analysis"
    )
    parser.add_argument(
        "--model",
        default="qwen2.5:7b",
        help="Local Ollama model (default: qwen2.5:7b)"
    )
    parser.add_argument(
        "--ai-timeout",
        type=float,
        default=30,
        help="Ollama timeout in seconds (default: 30)"
    )

    parser.add_argument(
        "--simulation",
        action="store_true",
        help="Declare input telemetry as a controlled simulation"
    )

    args = parser.parse_args()

    if args.simulation and not (args.analyze_ai or args.ai_context):
        parser.error("--simulation requires --analyze-ai or --ai-context")

    if args.analyze_ai and (
        args.ai_context or args.report or args.summary
    ):
        parser.error(
            "--analyze-ai cannot be combined with other output modes"
        )

    if args.analyze_ai:
        import re

        if not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}",
            args.model,
        ):
            parser.error("Invalid Ollama model name")

        if not 0 < args.ai_timeout <= 120:
            parser.error("AI timeout must be between 0 and 120 seconds")

    if args.ai_context and (args.report or args.summary):
        parser.error("--ai-context cannot be combined with --report or --summary")

    if args.max_groups < 1 or args.max_findings < 1:
        parser.error("AI context limits must be positive")

    if args.summary and not args.report:
        parser.error("--summary requires --report")

    try:
        events = normalize_events(parse_jsonl(args.log_file))
        data_quality_warnings = validate_events(events)
        findings = detect_brute_force(events)
        findings.extend(detect_success_after_failures(events))
        findings.extend(detect_account_enumeration(events))
        findings.extend(detect_account_lockout(events))
        findings.extend(detect_privileged_group_change(events))

        severity_priority = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "informational": 4,
        }

        findings.sort(
            key=lambda finding: severity_priority.get(
                finding["severity"], 5
            )
        )
    except (FileNotFoundError, PermissionError, ValueError) as error:
        parser.exit(1, f"Error: {error}\n")

    if args.analyze_ai:
        report = build_analysis_report(events, findings, data_quality_warnings)
        try:
            result = analyze_soc_report(
                report,
                model=args.model,
                timeout=args.ai_timeout,
                max_groups=args.max_groups,
                max_findings=args.max_findings,
                simulation=args.simulation,
            )
        except (OllamaClientError, ValueError) as error:
            parser.exit(1, f"AI analysis failed: {error}\n")
    elif args.ai_context:
        report = build_analysis_report(events, findings, data_quality_warnings)
        result = build_ai_context(
            report,
            max_groups=args.max_groups,
            max_findings=args.max_findings,
            simulation=args.simulation,
        )
    elif args.report:
        result = build_analysis_report(events, findings, data_quality_warnings)
    else:
        result = findings
    result_json = (
        format_summary(result)
        if args.summary
        else json.dumps(result, indent=2)
    )

    if args.output:
        output_path = Path(args.output)
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with output_path.open("x", encoding="utf-8") as output_file:
                output_file.write(result_json + "\n")
        except (FileExistsError, PermissionError, OSError) as error:
            parser.exit(1, f"Error saving results: {error}\n")

        print(f"Results saved to: {output_path}")
    else:
        print(result_json)


if __name__ == "__main__":
    main()
