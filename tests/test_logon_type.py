"""Tests for Windows Logon Type normalization."""

from soc_assistant.normalizer import normalize_event


def test_network_logon_type():
    event = {
        "data": {
            "win": {
                "system": {"eventID": "4625"},
                "eventdata": {"logonType": "3"},
            }
        }
    }

    result = normalize_event(event)

    assert result["logon_type"] == "3"


def test_interactive_logon_type():
    event = {
        "data": {
            "win": {
                "system": {"eventID": "4624"},
                "eventdata": {"logonType": "2"},
            }
        }
    }

    result = normalize_event(event)

    assert result["logon_type"] == "2"


def test_missing_logon_type():
    event = {
        "data": {
            "win": {
                "system": {"eventID": "4625"},
                "eventdata": {},
            }
        }
    }

    result = normalize_event(event)

    assert result["logon_type"] is None
