
# LogVigil

LogVigil is a local Python-based SOC log analyzer designed for defensive security monitoring and investigation.

## Features

- JSONL security log parsing
- Windows and Wazuh event normalization
- Five detection rules (DET-001 to DET-005)
- Investigation correlation and grouping
- Structured JSON reports
- Human-readable SOC summaries
- Command-line interface
- Optional local AI analysis (experimental)

## Detection Rules

- **DET-001:** Five failed logins within five minutes
- **DET-002:** Successful login following five failed attempts
- **DET-003:** Failed logins targeting five distinct usernames from one source
- **DET-004:** Account lockout detected
- **DET-005:** Privileged group membership changed

## Requirements

- Python 3.13

## Installation

Create a Python virtual environment and install the project:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

## Usage

Display available CLI options:

```bash
logvigil --help
```

Analyze a JSONL security log:

```bash
logvigil events.jsonl
```

Generate a structured JSON report:

```bash
logvigil events.jsonl --report
```

Generate a human-readable SOC summary:

```bash
logvigil events.jsonl --report --summary
```

Save the JSON report to a file:

```bash
logvigil events.jsonl --report --output report.json
```

Use synthetic or explicitly authorized security logs.

## Testing

Install development dependencies:

```bash
python -m pip install -e ".[dev]"
```

Run the automated test suite:

```bash
python -m pytest -q
```

## Package Build

Install the Python build tool:

```bash
python -m pip install build
```

Build the distribution packages:

```bash
python -m build
```

Generated packages are stored in the `dist/` directory.

## Security

- Designed for local defensive security analysis
- No automatic execution of AI recommendations
- Human review required for AI-generated advice
- Use synthetic or authorized logs only
- AI analysis is experimental and must not be treated as a verified security decision

## AI Integration

LogVigil includes experimental components for communicating with a local Ollama-based language model.

The planned model is Qwen.

The AI components have been tested with mocked responses, but a live Ollama/Qwen connection has not yet been validated.

AI-generated findings and recommendations require human verification.

## Project Status

**Current version:** 0.1.0

**Target version:** 1.0.0

Core detection, reporting, and CLI functionality have been tested.

Distribution packages have been built successfully, and the Wheel package has been installed and launched in an isolated environment.

The Ollama/Qwen integration has not yet been validated against a live model.

LogVigil remains under active development.

