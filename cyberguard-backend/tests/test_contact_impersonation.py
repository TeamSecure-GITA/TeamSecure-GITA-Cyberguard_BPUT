import pytest
from fastapi import HTTPException
import main

from contact_impersonation import build_style_profile, compare_contact_message


SAMPLES = [
    "Hi team, I will send the draft tomorrow. Please review the notes before lunch.",
    "Hello team, I will share the draft today. Please review the notes before lunch.",
    "Hi everyone, I will send the notes tomorrow. Please review the draft before lunch.",
]


def test_known_contact_message_with_matching_identity_and_style_has_no_extra_risk():
    profile = build_style_profile(SAMPLES)
    result = compare_contact_message(
        "From: Jane Doe <jane@bput.ac.in>\n\nHi team, I will send the draft tomorrow. Please review the notes before lunch.",
        ["jane@bput.ac.in"],
        profile,
    )

    assert result["sender_match"] is True
    assert result["risk_score"] == 0
    assert result["indicators"] == []


def test_compromised_contact_message_emits_identity_and_style_signals():
    profile = build_style_profile(SAMPLES)
    result = compare_contact_message(
        "From: Jane Doe <attacker@example.net>\n\nURGENT!!! wire transfer now!!! 🚨🚨 Buy gift cards immediately!!!",
        ["jane@bput.ac.in"],
        profile,
    )

    assert result["sender_match"] is False
    assert result["risk_score"] >= 25
    assert any(item["name"] == "Known Contact Sender Mismatch" for item in result["indicators"])
    assert result["caveat"].endswith("not proof of impersonation.")


def test_known_email_in_display_name_does_not_override_spoofed_sender_address():
    profile = build_style_profile(SAMPLES)
    result = compare_contact_message(
        "From: jane@bput.ac.in <attacker@example.net>\n\nHi team, I will send the draft tomorrow. Please review the notes before lunch.",
        ["jane@bput.ac.in"],
        profile,
    )

    assert result["sender_match"] is False
    assert any(item["name"] == "Known Contact Sender Mismatch" for item in result["indicators"])


def test_contact_style_profile_requires_multiple_examples():
    with pytest.raises(ValueError, match="At least three"):
        build_style_profile(["one example", "another example"])


def test_contact_profiles_are_private_and_used_by_impersonation_analysis(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "known-contacts.db")
    main.initialize_database()
    analyst = {"username": "analyst", "role": "analyst"}
    lead = {"username": "lead", "role": "lead"}
    contact = main.create_known_contact(
        {
            "name": "Jane Doe",
            "identifiers": ["jane@bput.ac.in"],
            "sample_messages": SAMPLES,
        },
        analyst,
    )

    assert main.list_known_contacts(analyst)["contacts"][0]["id"] == contact["id"]
    assert main.list_known_contacts(lead)["contacts"] == []
    request = main.ThreatAnalysisRequest(
        category="impersonation",
        payload="From: Jane Doe <attacker@example.net>\n\nURGENT!!! wire transfer now!!! 🚨🚨 Buy gift cards immediately!!!",
        metadata={"known_contact_id": contact["id"]},
    )
    result = main.analyze_threat(request, analyst)

    assert result["assessment"]["known_contact_comparison"]["sender_match"] is False
    assert any(item["name"] == "Known Contact Sender Mismatch" for item in result["assessment"]["indicators"])
    with pytest.raises(HTTPException) as error:
        main.apply_known_contact_comparison({}, "impersonation", request.payload, request.metadata, lead)
    assert error.value.status_code == 404
    assert main.delete_known_contact(contact["id"], analyst)["status"] == "deleted"