"""Optional local RAG integration regression tests."""
from pathlib import Path
from unittest.mock import patch
import pytest
from soc_assistant.ai_pipeline import analyze_soc_report


def test_rag_is_opt_in_and_uses_only_rule_ids():
    report = {"application": "LogVigil", "schema_version": "1.0"}
    context = {"application": "LogVigil", "context_version": "1.0",
               "summary": {"events_analyzed": 0, "findings_count": 0},
               "simulation_status": "unknown", "investigations": [
                   {"findings": [{"rule_id": "DET-004", "username": "PRIVATE_USER"}]}
               ]}
    with patch('soc_assistant.ai_pipeline.build_ai_context', return_value=context), \
         patch('soc_assistant.ai_pipeline.build_ai_request', return_value={"system": "safe", "user": "telemetry", "response_format": "json"}), \
         patch('soc_assistant.ai_pipeline.build_reference_context', return_value={"references": [{"title": "lockout", "excerpt": "reference"}]} ) as retrieve, \
         patch('soc_assistant.ai_pipeline.analyze_with_ollama', side_effect=RuntimeError('captured')) as ollama:
        with pytest.raises(RuntimeError, match='captured'):
            analyze_soc_report(report, rag_directory=Path('knowledge'))
        query = retrieve.call_args.args[0]
        assert 'DET-004' in query
        assert 'PRIVATE_USER' not in query
        request = ollama.call_args.args[0]
        assert request['system'] == 'safe'
        assert 'UNTRUSTED LOCAL REFERENCE DATA' in request['user']


def test_rag_disabled_does_not_retrieve():
    report = {"application": "LogVigil", "schema_version": "1.0"}
    context = {"application": "LogVigil", "context_version": "1.0",
               "summary": {"events_analyzed": 0, "findings_count": 0},
               "simulation_status": "unknown", "investigations": []}
    with patch('soc_assistant.ai_pipeline.build_ai_context', return_value=context), \
         patch('soc_assistant.ai_pipeline.build_ai_request', return_value={"system": "safe", "user": "telemetry", "response_format": "json"}), \
         patch('soc_assistant.ai_pipeline.build_reference_context') as retrieve, \
         patch('soc_assistant.ai_pipeline.analyze_with_ollama', side_effect=RuntimeError('captured')):
        with pytest.raises(RuntimeError, match='captured'):
            analyze_soc_report(report)
        retrieve.assert_not_called()
