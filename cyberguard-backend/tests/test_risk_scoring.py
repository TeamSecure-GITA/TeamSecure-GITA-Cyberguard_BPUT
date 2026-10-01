import json

import main
from risk_scoring import score_event
from threat_fusion import score_explainability


def test_score_event_normalizes_indicator_shares_without_changing_detector_risk():
    assessment = {
        "risk_score": 81,
        "risk_level": "Critical",
        "explanation_summary": "Credential request and sender mismatch were detected.",
        "indicators": [
            {"name": "Sender mismatch", "score": "99%", "weight": 2},
            {"name": "Credential request", "score": "88%", "weight": 1},
            {"name": "Urgency", "score": "73%", "weight": 1},
        ],
    }

    result = score_event(assessment)

    assert result["risk_score"] == 81
    assert [item["score"] for item in result["indicators"]] == ["50%", "25%", "25%"]
    assert sum(item["contribution"] for item in result["indicators"]) == 81
    assert all(item["score_kind"] == "evidence_share" for item in result["indicators"])
    assert "not probabilities" in result["scoring"]["interpretation"]


def test_score_event_handles_zero_signals_without_inventing_evidence():
    result = score_event({"risk_score": 14, "risk_level": "Safe", "indicators": []})

    assert result["risk_score"] == 14
    assert result["indicators"] == []
    assert result["scoring"]["contributions_total"] == 0


def test_legacy_explainability_reports_unavailable_instead_of_synthetic_score():
    result = score_explainability({
        "risk_score": 55,
        "assessment": {"indicators": [{"name": "Legacy signal", "score": "90%"}]},
    })

    assert result["contribution_status"] == "unavailable_for_legacy_incident"
    assert result["risk_score"] == 55
    assert result["contributions"] == []
    assert "explainability_score" not in result


def test_store_incident_persists_centralized_scoring(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "risk-scoring.db")
    main.initialize_database()
    assessment = {
        "risk_score": 40,
        "risk_level": "Medium",
        "explanation_summary": "Suspicious request matched.",
        "indicators": [{"name": "Request coercion", "score": "87%", "weight": 25}],
    }

    incident_id = main.store_incident("impersonation", "urgent transfer", assessment)
    with main.get_db() as db:
        stored = db.execute("SELECT assessment FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    stored_assessment = json.loads(stored["assessment"])

    assert stored_assessment["scoring"]["method"] == "evidence_weighted_attribution_v1"
    assert stored_assessment["indicators"][0]["score"] == "100%"
    assert stored_assessment["indicators"][0]["contribution"] == 40