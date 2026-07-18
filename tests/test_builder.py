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

"""Builder internals: grading, normalization, sealing, and parsing."""

from __future__ import annotations

import json

import pytest

from iso20022_evidence_pack_mcp import builder
from iso20022_evidence_pack_mcp.errors import InvalidInputError
from iso20022_evidence_pack_mcp.models import EvidencePack


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (90, "A"),
        (95, "A"),
        (75, "B"),
        (80, "B"),
        (50, "C"),
        (60, "C"),
        (49, "F"),
        (0, "F"),
    ],
)
def test_grade_bands(score: int, expected: str) -> None:
    """Each readiness score maps into the correct letter band."""
    assert builder.grade(score) == expected


def test_severity_top_level_wins() -> None:
    """A valid top-level severity is used verbatim (context ignored)."""
    assert builder._severity({"severity": "warning"}) == "warning"


def test_severity_from_nested_context() -> None:
    """A nested ``context.severity`` is used when no top-level one is set."""
    assert builder._severity({"context": {"severity": "info"}}) == "info"


def test_severity_unknown_value_clamped_to_error() -> None:
    """An out-of-vocabulary severity is clamped to ``error``."""
    assert builder._severity({"severity": "critical"}) == "error"


def test_severity_missing_defaults_to_error() -> None:
    """A finding with neither top-level nor nested severity is ``error``."""
    assert builder._severity({}) == "error"


def test_severity_non_dict_context_ignored() -> None:
    """A non-dict ``context`` yields no nested severity."""
    assert builder._severity({"context": "oops"}) == "error"


def test_finding_from_non_dict_is_malformed() -> None:
    """A non-dict finding becomes an ``EP_MALFORMED_FINDING``."""
    finding = builder._finding("not-a-dict")
    assert finding.code == "EP_MALFORMED_FINDING"
    assert finding.explanation == "not-a-dict"


def test_finding_from_dict_is_normalized() -> None:
    """A dict finding is normalized field-by-field."""
    finding = builder._finding(
        {
            "code": "X",
            "locator": "/a",
            "explanation": "e",
            "severity": "info",
        }
    )
    assert (finding.code, finding.locator, finding.explanation) == (
        "X",
        "/a",
        "e",
    )
    assert finding.severity == "info"


def test_finding_dict_defaults() -> None:
    """A dict finding without fields falls back to ``UNKNOWN``/defaults."""
    finding = builder._finding({})
    assert finding.code == "UNKNOWN"
    assert finding.locator == "/"
    assert finding.explanation == ""
    assert finding.severity == "error"


def test_findings_non_list_is_empty() -> None:
    """A non-list findings value normalizes to an empty tuple."""
    assert builder._findings("nope") == ()


def test_findings_list_is_tuple() -> None:
    """A list of findings normalizes to a tuple of :class:`Finding`."""
    findings = builder._findings([{"code": "A"}, {"code": "B"}])
    assert [f.code for f in findings] == ["A", "B"]


def test_readiness_section_requires_object() -> None:
    """A non-object readiness input is rejected."""
    with pytest.raises(InvalidInputError) as info:
        builder._readiness_section([])
    assert info.value.locator == "/readiness_content"


def test_readiness_section_non_int_score_is_zero() -> None:
    """A non-integer score is coerced to zero."""
    section = builder._readiness_section({"readiness_score": "high"})
    assert section.readiness_score == 0


@pytest.mark.parametrize(
    ("raw_score", "expected"),
    [(150, 100), (-5, 0), (73, 73)],
)
def test_readiness_section_clamps_score(raw_score: int, expected: int) -> None:
    """Scores are clamped into the 0..100 range."""
    section = builder._readiness_section({"readiness_score": raw_score})
    assert section.readiness_score == expected


def test_remediation_section_requires_object() -> None:
    """A non-object remediation input is rejected."""
    with pytest.raises(InvalidInputError) as info:
        builder._remediation_section("nope")
    assert info.value.locator == "/remediation_content"


def test_remediation_section_non_list_fixes_log_is_empty() -> None:
    """A non-list ``fixes_log`` normalizes to an empty tuple."""
    section = builder._remediation_section({"fixes_log": "oops"})
    assert section.fixes_log == ()


def test_remediation_section_list_fixes_log_stringified() -> None:
    """A list ``fixes_log`` is stringified element-by-element."""
    section = builder._remediation_section(
        {"remediation_applied": True, "fixes_log": ["a", 2]}
    )
    assert section.remediation_applied is True
    assert section.fixes_log == ("a", "2")


def test_simulated_requires_list() -> None:
    """A non-list simulation input is rejected."""
    with pytest.raises(InvalidInputError) as info:
        builder._simulated({})
    assert info.value.locator == "/simulation_content"


def test_simulated_item_must_be_object() -> None:
    """A non-object simulated response is rejected."""
    with pytest.raises(InvalidInputError) as info:
        builder._simulated([{"status": "ACCP"}, "oops"])
    assert info.value.locator == "/simulation_content"


def test_simulated_normalizes_items() -> None:
    """Simulated responses are normalized field-by-field."""
    responses = builder._simulated(
        [{"status": "ACCP", "generated_response_type": "pacs.002"}]
    )
    assert responses[0].status == "ACCP"
    assert responses[0].generated_response_type == "pacs.002"


def test_canonical_bytes_excludes_digest() -> None:
    """The canonical form never contains the ``digest`` field."""
    pack = EvidencePack(digest="sha256:deadbeef")
    assert b"digest" not in builder.canonical_bytes(pack)


def test_compute_digest_is_sha256_prefixed_and_stable() -> None:
    """The digest is ``sha256:``-prefixed and reproducible."""
    pack = EvidencePack()
    digest = builder.compute_digest(pack)
    assert digest.startswith("sha256:")
    assert digest == builder.compute_digest(pack)


def test_build_pack_full_is_graded_and_sealed() -> None:
    """A full build grades the readiness score and seals the pack."""
    pack = builder.build_pack(
        {"readiness_score": 95},
        {"remediation_applied": True},
        [{"status": "ACCP"}],
        {"institution": "Acme"},
    )
    assert pack.grade == "A"
    assert pack.remediation is not None
    assert pack.simulated_responses[0].status == "ACCP"
    assert pack.digest == builder.compute_digest(pack)


def test_build_pack_readiness_only() -> None:
    """A build with no remediation or simulation leaves those unset."""
    pack = builder.build_pack({"readiness_score": 10}, None, None, {})
    assert pack.grade == "F"
    assert pack.remediation is None
    assert pack.simulated_responses == ()


def test_parse_pack_round_trips_a_sealed_pack() -> None:
    """A sealed pack survives a JSON round-trip through ``parse_pack``."""
    original = builder.build_pack({"readiness_score": 80}, None, None, {})
    parsed = builder.parse_pack(original.model_dump_json())
    assert parsed == original


def test_parse_pack_rejects_bad_json() -> None:
    """Unparseable JSON raises :class:`InvalidInputError`."""
    with pytest.raises(InvalidInputError) as info:
        builder.parse_pack("{not json")
    assert "not valid JSON" in info.value.explanation


def test_parse_pack_rejects_schema_violation() -> None:
    """A pack whose score is out of range fails schema validation."""
    bad = json.dumps({"readiness": {"readiness_score": 150}})
    with pytest.raises(InvalidInputError) as info:
        builder.parse_pack(bad)
    assert "does not match the evidence-pack schema" in info.value.explanation
    assert info.value.context["errors"]
