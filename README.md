
# LogVigil

**LogVigil v1.0.0 — Local SOC Log Analyzer with Optional AI Assistance**

LogVigil is a Python-based Security Operations Center (SOC) log analyzer designed for defensive security monitoring, detection, investigation, and learning.

It processes Windows Security events from JSONL files, including supported Wazuh event structures, and generates structured findings and investigation reports.

LogVigil also supports automated SMB log import, an offline SOC dashboard, and optional local AI-assisted analysis using Ollama, Qwen3, and retrieval-augmented generation (RAG).

**Detection decisions are rule-based. AI analysis is advisory only.**

## Features

- JSONL security log parsing and validation
- Windows and supported Wazuh event normalization
- Five rule-based security detections
- Investigation correlation and grouping
- Structured JSON reports
- Human-readable SOC summaries
- Command-line interface
- Automated SMB log import
- Duplicate prevention using SHA-256
- Offline, read-only HTML dashboard
- Bounded AI investigation context
- Optional local Ollama/Qwen3 analysis
- Optional local RAG knowledge retrieval
- AI response and evidence validation
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

Findings require analyst review. A detection does not independently confirm malicious activity.

## Requirements

- Python 3.13
- macOS, Linux, or Windows for the core CLI
- Ollama and a compatible local model for optional AI analysis
- Mounted SMB share for the optional macOS importer

The SMB automation and dashboard were developed and tested in a controlled macOS and Windows Hyper-V lab environment.

## Installation

Create and activate a Python virtual environment.

On macOS or Linux:

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

## Automated SMB Log Import

LogVigil v1.0.0 includes a macOS SMB importer:

`src/soc_assistant/logvigil_smb_import.py`

The importer analyzes Windows Security JSONL exports from a mounted SMB share.

In the tested lab configuration:

- A Windows PowerShell exporter runs through Task Scheduler.
- A macOS LaunchAgent periodically runs the importer.
- The configured intervals are approximately 15 minutes.
- Source files remain on the SMB share.

The importer:

- Validates export filenames.
- Applies file size and minimum age limits.
- Processes up to 20 files per run.
- Uses SHA-256 hashes to prevent duplicate processing.
- Uses a local lock to prevent concurrent executions.
- Saves analysis summaries locally.
- Updates import state after successful analysis.
- Does not modify or delete SMB source files.
- Does not automatically invoke AI analysis.

### SMB Import Limitations

The SMB share must remain mounted and accessible.

The configured macOS LaunchAgent requires an available user session.

The Windows exporter applies event count, file size, and storage limits.

There is no end-to-end acknowledgment protocol between the exporter and importer. Export delivery is therefore not guaranteed.

Export retention and disk consumption require monitoring.

A dashboard generation failure can occur after an import has already been recorded as successful.

The SMB workflow is intended for an authorized local lab, not production-grade guaranteed-delivery log transport.

## Offline SOC Dashboard

LogVigil includes a local dashboard generator:

`src/soc_assistant/logvigil_dashboard.py`

The dashboard is a static, read-only HTML page generated from stored analysis summaries.

It displays:

- Number of analyzed files represented in the dashboard
- Total analyzed events
- Security findings
- Data quality warnings
- Investigation groups
- Highest severity per file
- Recent analysis summaries

The dashboard displays up to 100 recent valid summaries.

It does not provide live monitoring or automatic browser refresh.

Counts represent stored analysis summaries, not deduplicated security incidents.

## Local AI Integration

LogVigil supports optional local AI analysis through Ollama.

The tested model is Qwen3 4B:

`qwen3:4b`

The default local Ollama endpoint is:

`http://127.0.0.1:11434/api/chat`

Install Ollama separately and download the model:

```bash
ollama pull qwen3:4b
```

Verify the model:

```bash
ollama list
```

Run AI-assisted analysis:

```bash
logvigil events.jsonl --analyze-ai --model qwen3:4b --ai-timeout 120
```

The CLI retains `qwen2.5:7b` as its previously documented default model. Specify `--model qwen3:4b` when using the tested Qwen3 configuration.

AI analysis is optional. Core detection and reporting do not require Ollama.

## Local RAG Integration

LogVigil v1.0.0 introduces optional local retrieval-augmented generation (RAG).

The implementation is located in:

`src/soc_assistant/local_rag.py`

Reference material is stored in the project's `knowledge/` directory.

Run AI-assisted analysis with RAG:

```bash
logvigil events.jsonl --analyze-ai --rag --model qwen3:4b
```

The `--rag` option requires `--analyze-ai`.

The retrieval process selects relevant local reference material and supplies it to the AI as untrusted reference context.

### Included Knowledge Material

The initial knowledge base contains an original LogVigil training note about Windows account lockouts and Event ID 4740.

The note explains that account lockouts should be correlated with related authentication events before drawing conclusions.

**The included reference is not an official Microsoft, MITRE, or NIST publication.**

The current RAG implementation is a small local reference-retrieval system, not a comprehensive cybersecurity knowledge base.

### RAG Safety Boundaries

- RAG is optional.
- Reference material is treated as untrusted data.
- Retrieved text is not security evidence.
- Retrieved text cannot authorize response actions.
- AI recommendations require human review.
- No AI-generated instructions are executed automatically.

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

These fields communicate that AI analysis must not be treated as authorization to perform security actions.

## AI Limitations

Local language models can generate incorrect or unsupported statements even when their JSON responses are valid.

Observed limitations during earlier evaluations included:

- Confusing IP addresses with compromised accounts
- Incorrectly describing investigation group counts
- Referencing an incorrect RFC number
- Making unsupported assumptions about user privileges
- Focusing on metadata instead of security implications

RAG may provide useful context but does not guarantee factual accuracy.

Analysts must verify observations, hypotheses, and recommendations against the original security evidence.

LogVigil is not an autonomous incident response system.

## Security

LogVigil is designed for defensive security analysis.

Implemented safeguards include:

- Rule-based detection independent of AI
- Optional AI execution
- Loopback Ollama endpoint by default
- Bounded AI investigation context
- AI response and evidence validation
- Human review required for AI recommendations
- No automatic execution of AI recommendations
- Separation of trusted instructions and untrusted data
- Input size and parsing limits
- HTTP redirects disabled in the Ollama client
- Proxy use disabled for local Ollama requests
- No automatic deletion of SMB source files by the importer

These safeguards reduce risk but do not guarantee that the software is free of vulnerabilities.

Use synthetic or explicitly authorized security logs.

Never commit private telemetry, credentials, authentication tokens, or sensitive production data to a public repository.

## Testing

Install development dependencies:

```bash
python -m pip install -e ".[dev]"
```

Run automated tests:

```bash
python -m pytest -q
```

### Version 1.0.0 Validation

During v1.0.0 preparation:

- 400 automated tests passed.
- SMB importer and dashboard regression tests were added.
- A synthetic Windows Event ID 4740 scenario triggered DET-004.
- DET-004 was successfully analyzed using local Qwen3 and RAG.
- The AI output required human review and did not authorize execution.
- The SMB importer and dashboard were manually tested in the local lab.

These tests demonstrate selected functionality and safety properties. They do not establish production reliability or guarantee AI accuracy.

### Historical v0.1.0 Evaluation

The earlier v0.1.0 evaluation included:

- 271 automated tests passed
- 20,000 mixed synthetic Windows events processed in 4.006 seconds
- 4,000 findings produced in the mixed stress test
- 3,000 investigation groups produced in the mixed stress test
- 1,000 account enumeration scenarios detected from 5,000 events
- All five detection rules exercised in stress evaluations
- Three synthetic SOC scenarios analyzed successfully using live Ollama/Qwen3 4B

Performance measurements are environment-specific and are not guaranteed benchmarks.

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

A clean package build and installation check were completed as part of the v1.0.0 release validation.

## Project Status

**Latest stable version:** 1.0.0

**Release status:** v1.0.0 officially published on October 15, 2026.

### Phase 1 — Completed

The initial release included:

- Rule-based Windows security detection
- Investigation correlation
- JSON reporting
- SOC summaries
- Command-line interface
- Optional local Ollama/Qwen integration
- Automated regression testing
- Synthetic performance and detection evaluations
- Python package build and installation validation

**Published release:** [LogVigil v0.1.0](https://github.com/m-mehdi-sec/LogVigil/releases/tag/v0.1.0)

### Phase 2 — Implemented, Final Validation in Progress

The second development phase adds:

- Windows Security export integration from the Hyper-V lab
- Automated SMB-based import on macOS
- Local import state and duplicate prevention
- Offline HTML dashboard
- Optional local RAG knowledge retrieval
- Qwen3 integration with retrieved reference context
- Additional regression and integration testing
- Documentation of limitations and safety boundaries

### Future Development

Potential future improvements include:

- Broader authorized detection coverage
- Additional validated local knowledge sources
- Stronger export acknowledgment and retention controls
- More complete dashboard functionality
- Improved packaging and deployment automation

Autonomous security response capabilities are outside the scope of LogVigil v1.0.0 and belong to a separate future project.

LogVigil is a defensive learning and portfolio project, not a production-certified SOC platform.

## Author

**Muhammad Mehdi**

IT Security Developer Student
