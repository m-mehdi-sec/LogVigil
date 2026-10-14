
# LogVigil

**LogVigil v0.1.0 — Local SOC Log Analyzer with Optional AI Assistance**

LogVigil is a Python-based Security Operations Center (SOC) log analyzer designed for defensive security monitoring, detection, investigation, and learning.

It processes Windows security events from JSONL logs, including supported Wazuh event structures, and generates structured findings and investigation reports.

LogVigil can optionally use a locally hosted Ollama language model to assist with interpreting security findings.

**Detection decisions are rule-based. AI analysis is advisory only.**

## Features

- JSONL security log parsing
- Windows and Wazuh event normalization
- Five rule-based security detections
- Investigation correlation and grouping
- Structured JSON reports
- Human-readable SOC summaries
- Command-line interface
- Bounded AI investigation context
- Optional local Ollama/Qwen analysis
- AI response validation
- Human review required for AI recommendations
- No automatic security response actions

## Detection Rules

| Rule | Detection | Description |
|------|-----------|-------------|
| DET-001 | Repeated Failed Logins | Five or more failed Windows logins within five minutes |
| DET-002 | Success After Failures | Successful Windows login following repeated failed attempts |
| DET-003 | Multiple Usernames Targeted | Failed logins targeting at least five distinct usernames from the same source IP within five minutes |
| DET-004 | Account Lockout | Windows account lockout, Event ID 4740 |
| DET-005 | Privileged Group Change | Member added to a privileged Windows security group |

Supported privileged group membership event IDs include 4728, 4732, and 4756.

Findings require analyst review. A detection does not, by itself, confirm malicious activity.

## Requirements

- Python 3.13
- macOS, Linux, or Windows with a compatible Python environment
- Ollama and a compatible local model for optional AI analysis

The live AI integration has been tested on an Apple Silicon Mac with 16 GB RAM using Ollama 0.40.4 and Qwen3 4B.

## Installation

Create and activate a Python virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install LogVigil:

```bash
python -m pip install -e .
```

On Windows, use the appropriate virtual environment activation command for your shell.

## Command-Line Usage

Display available options:

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

Save a JSON report:

```bash
logvigil events.jsonl --report --output report.json
```

Generate bounded AI investigation context without invoking a model:

```bash
logvigil events.jsonl --ai-context
```

## Local AI Integration

LogVigil supports optional local AI analysis through Ollama.

The tested configuration is:

- Ollama 0.40.4
- Qwen3 4B (`qwen3:4b`)
- Local endpoint: `http://127.0.0.1:11434/api/chat`
- Non-streaming JSON responses
- Thinking mode disabled for the tested Qwen3 configuration

Install Ollama separately and download the model:

```bash
ollama pull qwen3:4b
```

Verify the model:

```bash
ollama list
```

Run local AI analysis:

```bash
logvigil events.jsonl --analyze-ai --model qwen3:4b --ai-timeout 120
```

Run a synthetic evaluation scenario:

```bash
logvigil evaluation/logs/soc_001_failed_logins.jsonl --analyze-ai --model qwen3:4b --ai-timeout 120
```

The CLI currently retains `qwen2.5:7b` as its default model name. Specify `--model qwen3:4b` when using the tested Qwen3 configuration.

AI analysis is optional. Core detection and reporting do not require Ollama.

## AI Analysis Output

The AI is instructed to return four structured fields:

- `risk_level`
- `observations`
- `hypotheses`
- `recommended_actions`

LogVigil validates the response structure and accepted risk levels.

AI-generated recommendations are advisory and require human review.

The output includes:

- `execution_authorized: false`
- `requires_human_review: true`

These fields communicate that the analysis must not be treated as authorization to perform security actions.

## AI Limitations

Local language models can generate incorrect or unsupported statements even when their JSON responses are valid.

Observed limitations during evaluation included:

- Confusing IP addresses with compromised accounts
- Incorrectly describing investigation group counts
- Referencing an incorrect RFC number
- Making unsupported assumptions about user privileges
- Focusing on metadata instead of security implications

A valid JSON response does not guarantee factual accuracy.

Analysts must verify observations, hypotheses, and recommendations against the original security evidence.

LogVigil is not an autonomous incident response system.

## Security

- Designed for defensive security analysis
- Uses a loopback Ollama endpoint by default
- Does not automatically execute AI recommendations
- Requires human review of AI-generated advice
- Separates trusted instructions from untrusted telemetry
- Applies limits to AI request and response sizes
- Validates AI response structure
- Disables HTTP redirects in the Ollama client
- Disables proxy use for local Ollama requests
- Does not require an external cloud AI service

Use synthetic or explicitly authorized security logs.

Avoid placing sensitive production telemetry into test datasets without appropriate authorization and handling controls.

## Testing

Install development dependencies:

```bash
python -m pip install -e ".[dev]"
```

Run automated tests:

```bash
python -m pytest -q
```

### Verified Evaluation Results

At the time of the v0.1.0 evaluation:

- 271 automated tests passed
- 20,000 mixed synthetic Windows events processed in 4.006 seconds
- 4,000 findings produced in the mixed stress test
- 3,000 investigation groups produced in the mixed stress test
- 1,000 account enumeration scenarios detected from 5,000 events
- All five detection rules exercised in stress evaluations
- Three synthetic SOC scenarios analyzed successfully using live Ollama/Qwen3 4B

Performance measurements are environment-specific and are not guaranteed benchmarks.

The live AI evaluations demonstrate integration functionality, not perfect analytical accuracy.

## Package Build

Install the build tool:

```bash
python -m pip install build
```

Build distribution packages:

```bash
python -m build
```

Generated packages are stored in `dist/`.

A previous Wheel package was installed and launched successfully in an isolated environment.

## Project Status

**Current version:** 0.1.0

**Long-term target:** 1.0.0

Implemented and tested:

- Rule-based Windows security detection
- Investigation correlation
- JSON reporting
- SOC summaries
- Command-line interface
- Optional local Ollama/Qwen integration

Remaining before the v0.1.0 release is finalized:

- Final regression and package-build verification
- Review of documentation and code changes
- Git commit and release checkpoint

LogVigil is a defensive learning and portfolio project, not a production-certified SOC platform.
