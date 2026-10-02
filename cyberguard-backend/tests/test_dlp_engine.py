import json

from dlp_engine import analyze_dlp
from detection_engine import analyze_technical_activity


def test_dlp_flags_sensitive_data_in_an_outbound_upload_without_echoing_values():
    payload = {
        "events": [
            {
                "event_type": "upload",
                "direction": "outbound",
                "content": "Card 4532015112830366 PAN ABCDE1234F credential ghp_abcdefghijklmnopqrstuvwxyz123456",
            }
        ]
    }

    result = analyze_dlp(payload)
    names = {indicator["name"] for indicator in result["indicators"]}

    assert result["risk_score"] >= 75
    assert result["sensitive_data_detected"] is True
    assert {
        "Payment Card Data",
        "PAN-like Identifier",
        "Credential or Private-Key Material",
    } <= names
    assert "4532015112830366" not in json.dumps(result)
    assert "ghp_abcdefghijklmnopqrstuvwxyz123456" not in json.dumps(result)


def test_dlp_flags_behavioral_egress_signals_and_is_wired_to_exfiltration_analysis():
    payload = json.dumps({
        "known_destinations": ["trusted.example"],
        "events": [
            {"event_type": "archive", "timestamp": "2026-10-01T22:30:00Z"},
            {
                "event_type": "upload",
                "timestamp": "2026-10-01T23:00:00Z",
                "destination": "drive.google.com",
                "bytes_out": 60_000_000,
                "user_baseline_bytes_out": 5_000_000,
            },
        ],
    })

    score, reasons, indicators = analyze_technical_activity(payload, "exfiltration")
    names = {indicator["name"] for indicator in indicators}

    assert score >= 90
    assert {
        "Large Egress Volume",
        "User Egress Baseline Deviation",
        "Rare Egress Destination",
        "Off-Hours Egress",
        "Personal Cloud Upload",
        "Archive-Then-Upload Sequence",
    } <= names
    assert reasons


def test_dlp_keeps_normal_traffic_and_invalid_card_numbers_unflagged():
    payload = {
        "known_destinations": ["trusted.example"],
        "flows": [
            {
                "destination": "trusted.example",
                "bytes_out": 4_000,
                "user_baseline_bytes_out": 2_000_000,
                "content": "Routine report contains invalid card-like number 4532015112830367.",
            }
        ],
    }

    result = analyze_dlp(payload)

    assert result == {
        "risk_score": 0,
        "indicators": [],
        "reasons": [],
        "sensitive_data_detected": False,
    }


def test_dlp_does_not_misclassify_inbound_sensitive_data_as_exfiltration():
    result = analyze_dlp({
        "events": [{
            "direction": "inbound",
            "content": "Card 4532015112830366",
        }]
    })

    assert result["risk_score"] == 0
    assert result["sensitive_data_detected"] is False


def test_dlp_ignores_malformed_input_without_claiming_an_exfiltration_finding():
    assert analyze_dlp("{malformed}") == {
        "risk_score": 0,
        "indicators": [],
        "reasons": [],
        "sensitive_data_detected": False,
    }
