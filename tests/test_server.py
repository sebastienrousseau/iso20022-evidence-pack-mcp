# Copyright (C) 2023-2026 Sebastien Rousseau.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""The FastMCP tool surface, seal determinism, and the ``main`` entry point."""

from __future__ import annotations

import json

import pytest

from iso20022_evidence_pack_mcp import __version__
from iso20022_evidence_pack_mcp import server as server_mod
from iso20022_evidence_pack_mcp.errors import InvalidInputError
from tests.conftest import (
    METADATA,
    READINESS_FULL,
    READINESS_MINIMAL,
    REMEDIATION_FULL,
    SIMULATION_FULL,
)

# --------------------------------------------------------------------------
# Internal helpers
# --------------------------------------------------------------------------


def test_as_detail_with_evidence_pack_error() -> None:
    """An :class:`EvidencePackError` keeps its own code and locator."""
    detail = server_mod._as_detail(InvalidInputError("boom", locator="/x"))
    assert detail.code == "EP_INVALID_INPUT"
    assert detail.locator == "/x"


def test_as_detail_with_generic_exception() -> None:
    """A plain exception collapses to the generic ``EP_ERROR`` detail."""
    detail = server_mod._as_detail(ValueError("kaboom"))
    assert detail.code == "EP_ERROR"
    assert "kaboom" in detail.explanation


def test_loads_parses_valid_json() -> None:
    """``_loads`` returns the parsed object for valid JSON."""
    assert server_mod._loads('{"a": 1}', "/x") == {"a": 1}


def test_loads_rejects_bad_json() -> None:
    """``_loads`` raises :class:`InvalidInputError` with the locator."""
    with pytest.raises(InvalidInputError) as info:
        server_mod._loads("{bad", "/x")
    assert info.value.locator == "/x"


# --------------------------------------------------------------------------
# build_evidence_pack
# --------------------------------------------------------------------------


def test_build_full_pack() -> None:
    """A full build returns a graded, sealed pack and rendered markdown."""
    result = server_mod.build_evidence_pack(
        readiness_content=json.dumps(READINESS_FULL),
        remediation_content=json.dumps(REMEDIATION_FULL),
        simulation_content=json.dumps(SIMULATION_FULL),
        metadata=METADATA,
    )
    assert result["error"] is None
    assert result["digest"].startswith("sha256:")
    assert result["pack"]["grade"] == "A"
    assert result["pack"]["remediation"] is not None
    assert len(result["pack"]["simulated_responses"]) == 2
    assert result["pack"]["metadata"] == METADATA
    assert "# ISO 20022 readiness evidence pack" in result["markdown"]


def test_build_readiness_only() -> None:
    """A readiness-only build leaves remediation and simulations unset."""
    result = server_mod.build_evidence_pack(
        readiness_content=json.dumps(READINESS_MINIMAL),
    )
    assert result["error"] is None
    assert result["pack"]["grade"] == "F"
    assert result["pack"]["remediation"] is None
    assert result["pack"]["simulated_responses"] == []
    assert result["pack"]["metadata"] == {}


def test_build_malformed_finding_becomes_placeholder() -> None:
    """A non-dict structural error surfaces as an ``EP_MALFORMED_FINDING``."""
    result = server_mod.build_evidence_pack(
        readiness_content=json.dumps(READINESS_FULL),
    )
    codes = [
        f["code"] for f in result["pack"]["readiness"]["structural_errors"]
    ]
    assert "EP_MALFORMED_FINDING" in codes


def test_build_bad_readiness_json_returns_error() -> None:
    """Unparseable readiness JSON returns an ``EP_INVALID_INPUT`` error."""
    result = server_mod.build_evidence_pack(readiness_content="{bad")
    assert result["pack"] is None
    assert result["error"]["code"] == "EP_INVALID_INPUT"
    assert result["error"]["locator"] == "/readiness_content"


def test_build_non_object_readiness_returns_error() -> None:
    """Readiness JSON that is not an object returns an error."""
    result = server_mod.build_evidence_pack(readiness_content="[]")
    assert result["pack"] is None
    assert result["error"]["code"] == "EP_INVALID_INPUT"


def test_build_bad_simulation_item_returns_error() -> None:
    """A simulation array with a non-object item returns an error."""
    result = server_mod.build_evidence_pack(
        readiness_content=json.dumps(READINESS_MINIMAL),
        simulation_content=json.dumps(["not-an-object"]),
    )
    assert result["pack"] is None
    assert result["error"]["code"] == "EP_INVALID_INPUT"
    assert result["error"]["locator"] == "/simulation_content"


# --------------------------------------------------------------------------
# Seal determinism and tamper-evidence
# --------------------------------------------------------------------------


def test_seal_reproduces_build_digest(full_pack_json: str) -> None:
    """Re-sealing a built pack reproduces the digest computed at build time."""
    build_digest = json.loads(full_pack_json)["digest"]
    result = server_mod.seal_pack(pack_content=full_pack_json)
    assert result["error"] is None
    assert result["digest"] == build_digest


def test_seal_bad_json_returns_error() -> None:
    """Sealing unparseable JSON returns an ``EP_INVALID_INPUT`` error."""
    result = server_mod.seal_pack(pack_content="{bad")
    assert result["digest"] == ""
    assert result["error"]["code"] == "EP_INVALID_INPUT"


def test_verify_correct_digest_is_true(full_pack_json: str) -> None:
    """Verifying a pack against its own seal reports ``verified`` true."""
    digest = json.loads(full_pack_json)["digest"]
    result = server_mod.verify_seal(
        pack_content=full_pack_json, expected_digest=digest
    )
    assert result["error"] is None
    assert result["verified"] is True
    assert result["computed_digest"] == digest


def test_verify_wrong_digest_is_false(full_pack_json: str) -> None:
    """Verifying against a wrong seal reports ``verified`` false."""
    result = server_mod.verify_seal(
        pack_content=full_pack_json, expected_digest="sha256:wrong"
    )
    assert result["error"] is None
    assert result["verified"] is False


def test_verify_detects_tampering(full_pack_json: str) -> None:
    """Tampering with a sealed field breaks verification."""
    pack = json.loads(full_pack_json)
    original_digest = pack["digest"]
    pack["grade"] = "A" if pack["grade"] != "A" else "F"
    tampered = json.dumps(pack)
    result = server_mod.verify_seal(
        pack_content=tampered, expected_digest=original_digest
    )
    assert result["verified"] is False


def test_verify_bad_json_returns_error() -> None:
    """Verifying unparseable JSON returns an ``EP_INVALID_INPUT`` error."""
    result = server_mod.verify_seal(
        pack_content="{bad", expected_digest="sha256:x"
    )
    assert result["error"]["code"] == "EP_INVALID_INPUT"


# --------------------------------------------------------------------------
# render_markdown
# --------------------------------------------------------------------------


def test_render_markdown_success(full_pack_json: str) -> None:
    """Rendering a valid pack returns a markdown report and no error."""
    result = server_mod.render_markdown(pack_content=full_pack_json)
    assert result["error"] is None
    assert "# ISO 20022 readiness evidence pack" in result["markdown"]


def test_render_markdown_bad_json_returns_error() -> None:
    """Rendering unparseable JSON returns an ``EP_INVALID_INPUT`` error."""
    result = server_mod.render_markdown(pack_content="{bad")
    assert result["markdown"] == ""
    assert result["error"]["code"] == "EP_INVALID_INPUT"


def test_render_schema_invalid_pack_returns_error() -> None:
    """A pack whose score is out of range fails schema validation."""
    bad = json.dumps({"readiness": {"readiness_score": 150}})
    result = server_mod.render_markdown(pack_content=bad)
    assert result["error"]["code"] == "EP_INVALID_INPUT"


# --------------------------------------------------------------------------
# main entry point
# --------------------------------------------------------------------------


def test_main_version_exits(capsys: pytest.CaptureFixture[str]) -> None:
    """``main(['--version'])`` prints the version and exits cleanly."""
    with pytest.raises(SystemExit) as info:
        server_mod.main(["--version"])
    assert info.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_main_runs_server(monkeypatch: pytest.MonkeyPatch) -> None:
    """``main([])`` parses args and hands off to the FastMCP run loop."""
    called: list[bool] = []
    monkeypatch.setattr(server_mod.server, "run", lambda: called.append(True))
    server_mod.main([])
    assert called == [True]
