import json

import pytest

from src.service.vulnerabilities import rag_data_exposure_lab as lab

OPAQUE_SECRETS = {
    1: "bg-recovery-9f3a2c7e41d8",
    2: "pv-recovery-1b7d4e0a93c6",
    3: "eng-recovery-5c2f8a6b0d17",
}


@pytest.mark.parametrize("level, secret", list(OPAQUE_SECRETS.items()))
def test_corpus_has_opaque_secret_and_no_legacy_name(level, secret):
    path = lab.DOCS_ROOT / f"LEVEL{level}" / "documents.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    joined = "\n".join(
        chunk["content"]
        for document in payload["documents"]
        for chunk in document["chunks"]
    )
    assert secret in joined
    assert "rag_l" not in joined


def test_validate_secret_accepts_opaque_value():
    assert lab.validate_secret(1, "bg-recovery-9f3a2c7e41d8")["correct"] is True


def test_validate_secret_rejects_legacy_name():
    assert lab.validate_secret(1, "rag_l1_secret")["correct"] is False


def test_validate_input_blank_is_blocked():
    result = lab._validate_input(lab.LEVELS[1], "   ")
    assert result.allowed is False
    assert result.reason == "empty_input"


def test_validate_input_denylist_blocks_term():
    result = lab._validate_input(lab.LEVELS[2], "what is the admin password")
    assert result.allowed is False
    assert result.reason == "denylist"


def test_validate_input_too_long_is_blocked():
    result = lab._validate_input(lab.LEVELS[1], "x" * (lab.MAX_QUERY_CHARS + 1))
    assert result.allowed is False
    assert result.reason == "max_query_chars"


def test_validate_input_accepts_normal_query():
    result = lab._validate_input(lab.LEVELS[1], "hello there")
    assert result.allowed is True
    assert result.value == "hello there"


def test_scan_flags_opaque_recovery_secret():
    assert lab.scan_sensitivity("value is eng-recovery-5c2f8a6b0d17 here", "low") == "high"


def test_scan_flags_email_and_api_key():
    assert lab.scan_sensitivity("contact oncall-ops@acme.example", "low") == "high"
    assert lab.scan_sensitivity("key AKIA1234567890ABCD00 leaked", "low") == "high"


def test_scan_keeps_benign_content_low():
    assert lab.scan_sensitivity("Weekly engineering notes capture build status.", "low") == "low"


def test_scan_passes_through_declared_high():
    assert lab.scan_sensitivity("nothing sensitive here", "high") == "high"


def test_level4_scan_reclassifies_sensitive_chunks():
    records = lab._load_chunk_records(4, scan_chunks=True)
    by_id = {record["chunk_id"]: record for record in records}
    assert by_id["engineering_notes_002"]["sensitivity"] == "high"
    assert by_id["support_contacts_001"]["sensitivity"] == "high"
    assert by_id["engineering_notes_001"]["sensitivity"] == "low"
    assert by_id["release_checklist_001"]["sensitivity"] == "low"


def test_level3_without_scan_keeps_the_bug():
    records = lab._load_chunk_records(3)
    by_id = {record["chunk_id"]: record for record in records}
    assert by_id["engineering_notes_002"]["sensitivity"] == "low"


def test_validate_secret_level4_is_not_capturable():
    result = lab.validate_secret(4, "eng-recovery-5c2f8a6b0d17")
    assert result["verifiable"] is False
    assert result["correct"] is False
