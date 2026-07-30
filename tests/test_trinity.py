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

"""The MCP prompt and resource surface (the "Trinity" beyond tools)."""

from __future__ import annotations

import json

from iso20022_evidence_pack_mcp import server as server_mod
from iso20022_evidence_pack_mcp.models import EvidencePack

# --------------------------------------------------------------------------
# audit_readiness_compliance prompt
# --------------------------------------------------------------------------


def test_prompt_is_registered() -> None:
    """The audit prompt is registered with its title and a single arg."""
    prompts = {
        p.name: p for p in server_mod.server._prompt_manager.list_prompts()
    }
    prompt = prompts["audit_readiness_compliance"]
    assert (
        prompt.title == "Audit an evidence pack for readiness and compliance"
    )
    assert [a.name for a in prompt.arguments or []] == ["evidence_pack_id"]
    arg = (prompt.arguments or [])[0]
    assert arg.required is False
    assert arg.description


def test_prompt_teaches_full_workflow() -> None:
    """The guidance names every tool in the intended audit order."""
    text = server_mod.audit_readiness_compliance()
    for tool in (
        "build_evidence_pack",
        "seal_pack",
        "sign_pack",
        "verify_seal",
        "verify_pack_signature",
        "render_markdown",
    ):
        assert tool in text


def test_prompt_default_branch_assembles_from_scratch() -> None:
    """With no id, the prompt tells the analyst to build a pack first."""
    text = server_mod.audit_readiness_compliance()
    assert "No pack identifier was supplied" in text
    assert "an ISO 20022 readiness evidence pack" in text


def test_prompt_identified_branch_anchors_on_the_id() -> None:
    """With an id, the prompt anchors the audit on that reference."""
    text = server_mod.audit_readiness_compliance("AUDIT-2026-01")
    assert "AUDIT-2026-01" in text
    assert "Locate the evidence pack referenced as" in text


# --------------------------------------------------------------------------
# Resources
# --------------------------------------------------------------------------


def test_resources_are_registered_without_templates() -> None:
    """Both static resources are listed; no templated resource exists."""
    uris = {
        str(r.uri)
        for r in server_mod.server._resource_manager.list_resources()
    }
    assert "evidence://schema" in uris
    assert "evidence://error-codes" in uris
    assert server_mod.server._resource_manager.list_templates() == []


def test_schema_resource_matches_the_pydantic_model() -> None:
    """The schema resource returns the EvidencePack JSON schema verbatim."""
    payload = json.loads(server_mod.evidence_pack_schema())
    assert payload == EvidencePack.model_json_schema()
    # The seal and the readiness section are part of the exposed contract.
    assert "digest" in payload["properties"]
    assert "readiness" in payload["properties"]


def test_error_codes_resource_mirrors_the_taxonomy() -> None:
    """The error-codes resource reflects each EvidencePackError subclass."""
    taxonomy = json.loads(server_mod.error_codes())
    by_code = {entry["code"]: entry for entry in taxonomy}
    assert set(by_code) == {
        "EP_ERROR",
        "EP_INVALID_INPUT",
        "EP_SEAL_MISMATCH",
        "EP_NO_SIGNING_KEY",
    }
    # Codes, names, and explanations come straight from the classes.
    for cls in server_mod._ERROR_CLASSES:
        entry = by_code[cls.code]
        assert entry["name"] == cls.__name__
        assert entry["explanation"] == (cls.__doc__ or "").strip()
        assert entry["explanation"]
