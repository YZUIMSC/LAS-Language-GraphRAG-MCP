"""Unit tests for CWE chain component importer.

All tests use mocked Neo4jClient — no real Neo4j required.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, call

import pytest

from cyber_graph_triage.importers.cwe_chain_components import (
    DEFAULT_PATCH_FILE,
    VALID_NATURES,
    build_import_params,
    load_patch_file,
    run_import,
    validate_chain,
    _validate_entry,
)


# ── fixtures ──────────────────────────────────────────────────────────────────

SAMPLE_ENTRY = {
    "source": "CWE-692",
    "nature": "FollowedBy",
    "target": "CWE-79",
    "target_name": "Cross-site Scripting",
    "source_type": "cwe_official_html",
    "source_url": "https://cwe.mitre.org/data/definitions/692.html",
    "notes": "Chain Components table.",
}

EXPECTED_PARAMS = {
    "source":      "CWE-692",
    "nature":      "FollowedBy",
    "target":      "CWE-79",
    "target_name": "Cross-site Scripting",
    "source_type": "cwe_official_html",
    "source_url":  "https://cwe.mitre.org/data/definitions/692.html",
    "notes":       "Chain Components table.",
}


def _mock_client(src_exists: bool = True, tgt_exists: bool = True) -> MagicMock:
    """Return a mock Neo4jClient whose run() behaves based on the given flags."""
    client = MagicMock()

    def _run(query: str, **kwargs):
        name = kwargs.get("name", "")
        if "MATCH (n:CWE" in query:
            # check-node query
            if name == "CWE-692":
                return [{"name": "CWE-692", "extended_name": "..."}] if src_exists else []
            if name == "CWE-79":
                return [{"name": "CWE-79", "extended_name": "..."}] if tgt_exists else []
            return []
        # import query — return a merged row
        return [{"source": kwargs.get("source"), "nature": kwargs.get("nature"),
                 "target": kwargs.get("target"), "target_name": kwargs.get("target_name")}]

    client.run.side_effect = _run
    return client


# ── load_patch_file ───────────────────────────────────────────────────────────

class TestLoadPatchFile:
    def test_loads_valid_file(self, tmp_path: Path) -> None:
        f = tmp_path / "patch.json"
        f.write_text(json.dumps([SAMPLE_ENTRY]))
        entries = load_patch_file(f)
        assert len(entries) == 1
        assert entries[0]["source"] == "CWE-692"

    def test_rejects_non_array(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.json"
        f.write_text(json.dumps({"source": "CWE-1"}))
        with pytest.raises(ValueError, match="JSON array"):
            load_patch_file(f)

    def test_rejects_invalid_source_format(self, tmp_path: Path) -> None:
        entry = {**SAMPLE_ENTRY, "source": "NOT-A-CWE"}
        f = tmp_path / "bad.json"
        f.write_text(json.dumps([entry]))
        with pytest.raises(ValueError, match="not a valid CWE ID"):
            load_patch_file(f)

    def test_rejects_invalid_target_format(self, tmp_path: Path) -> None:
        entry = {**SAMPLE_ENTRY, "target": "CVE-2021-12345"}
        f = tmp_path / "bad.json"
        f.write_text(json.dumps([entry]))
        with pytest.raises(ValueError, match="not a valid CWE ID"):
            load_patch_file(f)

    def test_rejects_invalid_nature(self, tmp_path: Path) -> None:
        entry = {**SAMPLE_ENTRY, "nature": "CausedBy"}
        f = tmp_path / "bad.json"
        f.write_text(json.dumps([entry]))
        with pytest.raises(ValueError, match="not a recognised"):
            load_patch_file(f)

    def test_rejects_missing_required_field(self, tmp_path: Path) -> None:
        entry = {"source": "CWE-1", "target": "CWE-2"}  # missing nature
        f = tmp_path / "bad.json"
        f.write_text(json.dumps([entry]))
        with pytest.raises(ValueError, match="missing required field 'nature'"):
            load_patch_file(f)

    def test_case_insensitive_cwe_ids(self, tmp_path: Path) -> None:
        entry = {**SAMPLE_ENTRY, "source": "cwe-692", "target": "cwe-79"}
        f = tmp_path / "patch.json"
        f.write_text(json.dumps([entry]))
        entries = load_patch_file(f)
        assert len(entries) == 1

    def test_default_patch_file_is_valid(self) -> None:
        entries = load_patch_file(DEFAULT_PATCH_FILE)
        assert len(entries) >= 1
        assert entries[0]["source"] == "CWE-692"
        assert entries[0]["nature"] == "FollowedBy"
        assert entries[0]["target"] == "CWE-79"


# ── _validate_entry ───────────────────────────────────────────────────────────

class TestValidateEntry:
    def test_valid_entry_has_no_errors(self) -> None:
        assert _validate_entry(SAMPLE_ENTRY, 0) == []

    def test_all_valid_natures_accepted(self) -> None:
        for nat in VALID_NATURES:
            entry = {**SAMPLE_ENTRY, "nature": nat}
            assert _validate_entry(entry, 0) == [], f"Nature '{nat}' should be valid"

    def test_non_dict_rejected(self) -> None:
        errors = _validate_entry("string", 0)
        assert any("must be a dict" in e for e in errors)


# ── build_import_params ───────────────────────────────────────────────────────

class TestBuildImportParams:
    def test_returns_expected_keys(self) -> None:
        params = build_import_params(SAMPLE_ENTRY)
        assert params == EXPECTED_PARAMS

    def test_source_and_target_uppercased(self) -> None:
        entry = {**SAMPLE_ENTRY, "source": "cwe-692", "target": "cwe-79"}
        params = build_import_params(entry)
        assert params["source"] == "CWE-692"
        assert params["target"] == "CWE-79"

    def test_optional_fields_default_to_empty_string(self) -> None:
        entry = {"source": "CWE-1", "nature": "FollowedBy", "target": "CWE-2"}
        params = build_import_params(entry)
        assert params["target_name"] == ""
        assert params["source_type"] == "cwe_chain_component_patch"
        assert params["source_url"] == ""
        assert params["notes"] == ""


# ── run_import (dry-run) ──────────────────────────────────────────────────────

class TestRunImportDryRun:
    def test_dry_run_does_not_call_neo4j(self) -> None:
        client = MagicMock()
        result = run_import(client, [SAMPLE_ENTRY], dry_run=True)
        client.run.assert_not_called()

    def test_dry_run_result_has_dry_run_status(self) -> None:
        client = MagicMock()
        result = run_import(client, [SAMPLE_ENTRY], dry_run=True, input_file="test.json")
        assert result["dry_run"] is True
        assert result["total"] == 1
        assert result["imported"] == 1
        assert result["skipped"] == 0
        assert result["results"][0]["status"] == "dry_run"

    def test_dry_run_with_multiple_entries(self) -> None:
        entries = [SAMPLE_ENTRY, {**SAMPLE_ENTRY, "nature": "ChildOf"}]
        client = MagicMock()
        result = run_import(client, entries, dry_run=True)
        assert result["total"] == 2
        assert result["imported"] == 2
        assert all(r["status"] == "dry_run" for r in result["results"])

    def test_dry_run_preserves_input_file(self) -> None:
        client = MagicMock()
        result = run_import(client, [SAMPLE_ENTRY], dry_run=True, input_file="/path/to/file.json")
        assert result["input_file"] == "/path/to/file.json"


# ── run_import (live, mocked client) ─────────────────────────────────────────

class TestRunImportLive:
    def test_successful_merge(self) -> None:
        client = _mock_client(src_exists=True, tgt_exists=True)
        result = run_import(client, [SAMPLE_ENTRY])
        assert result["imported"] == 1
        assert result["skipped"] == 0
        assert result["results"][0]["status"] == "merged"

    def test_skips_when_source_not_found(self) -> None:
        client = _mock_client(src_exists=False, tgt_exists=True)
        result = run_import(client, [SAMPLE_ENTRY])
        assert result["imported"] == 0
        assert result["skipped"] == 1
        assert result["results"][0]["status"] == "skipped"
        assert result["warnings"]

    def test_skips_when_target_not_found_and_no_placeholder(self) -> None:
        client = _mock_client(src_exists=True, tgt_exists=False)
        result = run_import(client, [SAMPLE_ENTRY], allow_create_placeholder=False)
        assert result["skipped"] == 1
        assert "allow-create-placeholder" in result["warnings"][0]

    def test_creates_placeholder_when_flag_set(self) -> None:
        client = _mock_client(src_exists=True, tgt_exists=False)
        result = run_import(client, [SAMPLE_ENTRY], allow_create_placeholder=True)
        assert result["imported"] == 1
        assert result["results"][0]["status"] == "merged_with_placeholder"
        assert result["warnings"]  # warns about placeholder creation

    def test_idempotent_merge_does_not_error(self) -> None:
        """Calling twice on same mock should not raise — MERGE semantics."""
        client = _mock_client(src_exists=True, tgt_exists=True)
        r1 = run_import(client, [SAMPLE_ENTRY])
        r2 = run_import(client, [SAMPLE_ENTRY])
        assert r1["imported"] == 1
        assert r2["imported"] == 1

    def test_neo4j_error_on_check_is_handled(self) -> None:
        client = MagicMock()
        client.run.side_effect = RuntimeError("connection refused")
        result = run_import(client, [SAMPLE_ENTRY])
        assert result["skipped"] == 1
        assert result["results"][0]["status"] == "skipped"


# ── cypher parameter correctness ──────────────────────────────────────────────

class TestCypherParams:
    """Verify that build_import_params generates the exact params expected by the Cypher."""

    REQUIRED_CYPHER_PARAMS = {
        "source", "nature", "target", "target_name",
        "source_type", "source_url", "notes",
    }

    def test_all_cypher_params_present(self) -> None:
        params = build_import_params(SAMPLE_ENTRY)
        assert self.REQUIRED_CYPHER_PARAMS <= set(params.keys())

    def test_source_is_cwe_692(self) -> None:
        params = build_import_params(SAMPLE_ENTRY)
        assert params["source"] == "CWE-692"

    def test_nature_is_followed_by(self) -> None:
        params = build_import_params(SAMPLE_ENTRY)
        assert params["nature"] == "FollowedBy"

    def test_target_is_cwe_79(self) -> None:
        params = build_import_params(SAMPLE_ENTRY)
        assert params["target"] == "CWE-79"


# ── validate_chain ────────────────────────────────────────────────────────────

class TestValidateChain:
    def _client_with_cwe(self, related_cwes: list[dict]) -> MagicMock:
        client = MagicMock()
        # lookup_cwe ultimately calls client.run with the CWE Cypher
        client.run.return_value = [{
            "cwe":         "CWE-692",
            "name":        "Incomplete Denylist to Cross-Site Scripting",
            "description": "...",
            "abstraction": "Compound",
            "structure":   "Chain",
            "status":      "Incomplete",
            "related_cwes": related_cwes,
            "capecs":      [],
            "mitigations": [],
            "consequences": [],
        }]
        return client

    def test_reports_present_relation(self, tmp_path: Path) -> None:
        related = [
            {"nature": "FollowedBy", "target": "CWE-79", "target_name": "XSS"},
            {"nature": "StartsWith", "target": "CWE-184", "target_name": "..."},
        ]
        client = self._client_with_cwe(related)
        patch = tmp_path / "p.json"
        patch.write_text(json.dumps([{
            "source": "CWE-692", "nature": "FollowedBy", "target": "CWE-79",
            "target_name": "XSS", "source_type": "t", "source_url": "", "notes": "",
        }]))
        result = validate_chain(client, "CWE-692", patch_file=patch)
        assert result["found"] is True
        assert "FollowedBy" in result["natures"]
        er = result["expected_relations"]
        assert er[0]["nature"] == "FollowedBy"
        assert er[0]["present"] is True
        assert result["warnings"] == []

    def test_reports_missing_relation(self, tmp_path: Path) -> None:
        related = [{"nature": "StartsWith", "target": "CWE-184", "target_name": "..."}]
        client = self._client_with_cwe(related)
        patch = tmp_path / "p.json"
        patch.write_text(json.dumps([{
            "source": "CWE-692", "nature": "FollowedBy", "target": "CWE-79",
            "target_name": "XSS", "source_type": "t", "source_url": "", "notes": "",
        }]))
        result = validate_chain(client, "CWE-692", patch_file=patch)
        er = result["expected_relations"]
        assert er[0]["present"] is False
        assert result["warnings"]  # should warn about missing relation

    def test_not_found_cwe(self) -> None:
        client = MagicMock()
        client.run.return_value = []
        result = validate_chain(client, "CWE-9999")
        assert result["found"] is False
        assert result["warnings"]
