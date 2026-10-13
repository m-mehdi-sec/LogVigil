# LogVigil

LogVigil is a local Python-based SOC log analyzer.

## Features

- JSONL security log parsing
- Windows and Wazuh event normalization
- Five detection rules (DET-001 to DET-005)
- Investigation correlation and grouping
- Structured JSON reports
- Human-readable SOC summaries
- Command-line interface
- Optional local AI analysis (experimental)

## Requirements

- Python 3.13

## Installation

Create a Python virtual environment and install the project:

    python3 -m venv .venv
    source .venv/bin/activate
    python -m pip install -e .

## Usage

    logvigil --help
    logvigil events.jsonl --report
    logvigil events.jsonl --summary
    logvigil events.jsonl --report --output report.json

## Testing

    python -m pip install -e ".[dev]"
    python -m pytest -q

## Security

- Local defensive analysis
- No automatic execution of AI recommendations
- Human review required for AI-generated advice
- Use synthetic or authorized logs only

## Status

Version: 0.1.0

Target: LogVigil v1.0

Core functionality is being finalized before testing the Ollama/Qwen integration.
