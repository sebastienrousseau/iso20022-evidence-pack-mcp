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

"""Markdown rendering: every conditional section of the report."""

from __future__ import annotations

from iso20022_evidence_pack_mcp import report
from iso20022_evidence_pack_mcp.models import (
    EvidencePack,
    Finding,
    ReadinessSection,
    RemediationSection,
    SimulatedResponse,
)


def test_finding_lines_format() -> None:
    """Each finding renders as a single, fully-populated bullet line."""
    lines = report._finding_lines(
        [Finding(code="X", locator="/a", explanation="e", severity="info")]
    )
    assert lines == ["- `X` (info) at `/a` — e"]


def test_render_full_pack_covers_every_section() -> None:
    """A fully-populated pack renders metadata and every content section."""
    pack = EvidencePack(
        metadata={"institution": "Acme", "reference": "R-1"},
        readiness=ReadinessSection(
            message_type="pain.001.001.09",
            is_valid=True,
            readiness_score=95,
            structural_errors=(Finding(code="S1", explanation="bad"),),
            profile_findings=(Finding(code="P1", explanation="warn"),),
        ),
        remediation=RemediationSection(
            remediation_applied=True,
            fixes_log=("Added Ctry",),
            residual_findings=(Finding(code="R1", explanation="left"),),
        ),
        simulated_responses=(
            SimulatedResponse(
                status="ACCP", generated_response_type="pacs.002"
            ),
        ),
        grade="A",
        digest="sha256:abc",
    )
    md = report.render_markdown(pack)
    assert "## Audit metadata" in md
    assert "- **institution**: Acme" in md
    assert "- `S1` (error) at `/` — bad" in md
    assert "- `P1` (error) at `/` — warn" in md
    assert "## Remediation" in md
    assert "- **Applied**: yes" in md
    assert "- Fix: Added Ctry" in md
    assert "- Residual findings:" in md
    assert "  - `R1` (error) at `/` — left" in md
    assert "## Simulated bank responses" in md
    assert "- `ACCP` via `pacs.002`" in md
    assert "(grade A)" in md
    assert "**Seal**: `sha256:abc`" in md


def test_render_minimal_pack_uses_none_placeholders() -> None:
    """An empty pack shows ``None.`` placeholders and omits optional blocks."""
    pack = EvidencePack()
    md = report.render_markdown(pack)
    assert "## Audit metadata" not in md
    assert "**Message type**: unknown" in md
    assert "**Structurally valid**: no" in md
    assert "**Seal**: `unsealed`" in md
    assert "## Structural errors\n- None." in md
    assert "## Profile findings\n- None." in md
    assert "## Remediation" not in md
    assert "## Simulated bank responses" not in md


def test_render_remediation_without_fixes_or_residual() -> None:
    """A remediation block with no fixes and no residual findings renders."""
    pack = EvidencePack(
        remediation=RemediationSection(remediation_applied=False),
    )
    md = report.render_markdown(pack)
    assert "## Remediation" in md
    assert "- **Applied**: no" in md
    assert "- Fix:" not in md
    assert "- Residual findings:" not in md
