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


def test_contact_style_profile_extracts_multilingual_words_and_scripts():
    samples = [
        "ମୁଁ ଆସନ୍ତାକାଲି ଦଳକୁ ଖସଡ଼ା ପଠାଇବି। ଦୟାକରି ମଧ୍ୟାହ୍ନ ପୂର୍ବରୁ ଟିପ୍ପଣୀ ଦେଖନ୍ତୁ।",
        "ମୁଁ ଆଜି ଦଳକୁ ଖସଡ଼ା ପଠାଇବି। ଦୟାକରି ମଧ୍ୟାହ୍ନ ପୂର୍ବରୁ ଟିପ୍ପଣୀ ଦେଖନ୍ତୁ।",
        "ମୁଁ କାଲି ଦଳକୁ ଟିପ୍ପଣୀ ପଠାଇବି। ଦୟାକରି ମଧ୍ୟାହ୍ନ ପୂର୍ବରୁ ଖସଡ଼ା ଦେଖନ୍ତୁ।",
    ]
    profile = build_style_profile(samples)

    matching = compare_contact_message(
        f"From: Jane Doe <jane@bput.ac.in>\n\n{samples[0]}",
        ["jane@bput.ac.in"],
        profile,
    )
    different_script = compare_contact_message(
        "From: Jane Doe <jane@bput.ac.in>\n\n"
        "Tomorrow the team will receive my complete draft for review before lunch. "
        "Please send your detailed comments when you have finished checking everything.",
        ["jane@bput.ac.in"],
        profile,
    )

    assert profile["script_distribution"]["ORIYA"] > 0.95
    assert matching["dominant_profile_script"] == "ORIYA"
    assert matching["dominant_message_script"] == "ORIYA"
    assert matching["risk_score"] == 0
    assert different_script["dominant_message_script"] == "LATIN"
    assert any(item["name"] == "Known Contact Script Deviation" for item in different_script["indicators"])


def test_short_message_reports_inconclusive_style_without_script_penalty():
    profile = build_style_profile([
        "ମୁଁ ଆସନ୍ତାକାଲି ଦଳକୁ ଖସଡ଼ା ପଠାଇବି। ଦୟାକରି ଟିପ୍ପଣୀ ଦେଖନ୍ତୁ।",
        "ମୁଁ ଆଜି ଦଳକୁ ଖସଡ଼ା ପଠାଇବି। ଦୟାକରି ଟିପ୍ପଣୀ ଦେଖନ୍ତୁ।",
        "ମୁଁ କାଲି ଦଳକୁ ଟିପ୍ପଣୀ ପଠାଇବି। ଦୟାକରି ଖସଡ଼ା ଦେଖନ୍ତୁ।",
    ])

    result = compare_contact_message(
        "From: Jane Doe <jane@bput.ac.in>\n\nThanks, okay.",
        ["jane@bput.ac.in"],
        profile,
    )

    assert result["style_comparison_status"] == "insufficient_text"
    assert result["message_word_count"] == 2
    assert result["risk_score"] == 0
    assert result["indicators"] == []


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
            "consent_confirmed": True,
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
    assert result["assessment"]["known_contact_comparison"]["style_comparison_status"] == "compared"
    assert result["assessment"]["known_contact_comparison"]["dominant_message_script"] == "LATIN"
    assert any(item["name"] == "Known Contact Sender Mismatch" for item in result["assessment"]["indicators"])
    with pytest.raises(HTTPException) as error:
        main.apply_known_contact_comparison({}, "impersonation", request.payload, request.metadata, lead)
    assert error.value.status_code == 404
    assert main.delete_known_contact(contact["id"], analyst)["status"] == "deleted"


def test_known_contact_creation_requires_explicit_consent(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "known-contact-consent.db")
    main.initialize_database()

    with pytest.raises(HTTPException, match="Explicit consent is required") as error:
        main.create_known_contact(
            {"name": "Jane Doe", "identifiers": ["jane@example.test"], "sample_messages": SAMPLES},
            {"username": "analyst", "role": "analyst"},
        )

    assert error.value.status_code == 400


def test_known_contact_profiles_expire_per_owner_after_retention_window(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "known-contact-retention.db")
    monkeypatch.setattr(main, "KNOWN_CONTACT_RETENTION_DAYS", 90)
    main.initialize_database()
    with main.get_db() as db:
        db.executemany(
            "INSERT INTO known_contacts (owner_username, name, identifiers, style_profile, created_at) VALUES (?, ?, ?, ?, ?)",
            [
                ("analyst", "Expired analyst", "[]", "{}", "2025-01-01T00:00:00+00:00"),
                ("lead", "Expired lead", "[]", "{}", "2025-01-01T00:00:00+00:00"),
            ],
        )

    assert main.list_known_contacts({"username": "analyst", "role": "analyst"})["contacts"] == []
    with main.get_db() as db:
        remaining = db.execute("SELECT owner_username FROM known_contacts").fetchall()

    assert [row["owner_username"] for row in remaining] == ["lead"]
