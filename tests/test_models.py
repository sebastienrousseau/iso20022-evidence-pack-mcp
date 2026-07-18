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

"""Evidence-pack schemas: defaults, immutability, and request strictness."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from iso20022_evidence_pack_mcp.models import (
    SCHEMA_VERSION,
    BuildRequest,
    BuildResponse,
    EvidencePack,
    Finding,
    ReadinessSection,
    RemediationSection,
    RenderRequest,
    SealRequest,
    SimulatedResponse,
    VerifyRequest,
)


def test_finding_defaults() -> None:
    """A :class:`Finding` defaults its locator, explanation and severity."""
    finding = Finding(code="X")
    assert finding.locator == "/"
    assert finding.explanation == ""
    assert finding.severity == "error"


def test_readiness_section_defaults() -> None:
    """A default :class:`ReadinessSection` is empty and invalid."""
    section = ReadinessSection()
    assert section.message_type == ""
    assert section.is_valid is False
    assert section.readiness_score == 0
    assert section.structural_errors == ()
    assert section.profile_findings == ()


def test_readiness_score_bounds_enforced() -> None:
    """The readiness score is constrained to the 0..100 range."""
    with pytest.raises(ValidationError):
        ReadinessSection(readiness_score=150)
    with pytest.raises(ValidationError):
        ReadinessSection(readiness_score=-1)


def test_remediation_and_simulated_defaults() -> None:
    """Remediation and simulated sections default to empty content."""
    remediation = RemediationSection()
    assert remediation.remediation_applied is False
    assert remediation.fixes_log == ()
    assert remediation.residual_findings == ()
    simulated = SimulatedResponse()
    assert simulated.status == ""
    assert simulated.generated_response_type == ""


def test_evidence_pack_defaults() -> None:
    """A default :class:`EvidencePack` carries the schema version."""
    pack = EvidencePack()
    assert pack.schema_version == SCHEMA_VERSION == "1.0"
    assert pack.metadata == {}
    assert isinstance(pack.readiness, ReadinessSection)
    assert pack.remediation is None
    assert pack.simulated_responses == ()
    assert pack.grade == "F"
    assert pack.digest == ""


def test_evidence_pack_is_frozen() -> None:
    """An :class:`EvidencePack` cannot be mutated after construction."""
    pack = EvidencePack()
    with pytest.raises(ValidationError):
        pack.grade = "A"  # type: ignore[misc]


def test_build_response_holds_a_pack() -> None:
    """A :class:`BuildResponse` can carry an assembled pack."""
    response = BuildResponse(pack=EvidencePack(), digest="sha256:abc")
    assert response.pack is not None
    assert response.digest == "sha256:abc"
    assert response.error is None


@pytest.mark.parametrize(
    "cls",
    [BuildRequest, SealRequest, VerifyRequest, RenderRequest],
)
def test_requests_forbid_extra_fields(cls: type) -> None:
    """Every request model rejects unexpected fields (``extra='forbid'``)."""
    with pytest.raises(ValidationError):
        cls(unexpected="x")  # type: ignore[call-arg]
