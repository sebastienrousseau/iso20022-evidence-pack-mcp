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

"""Render an evidence pack as a human-readable markdown compliance report."""

from __future__ import annotations

from collections.abc import Sequence

from iso20022_evidence_pack_mcp.models import EvidencePack, Finding


def _finding_lines(findings: Sequence[Finding]) -> list[str]:
    """Render a list of findings as markdown bullet lines."""
    return [
        f"- `{f.code}` ({f.severity}) at `{f.locator}` — {f.explanation}"
        for f in findings
    ]


def render_markdown(pack: EvidencePack) -> str:
    """Assemble a markdown compliance report for an evidence pack."""
    readiness = pack.readiness
    lines = [
        "# ISO 20022 readiness evidence pack",
        "",
        f"- **Schema version**: {pack.schema_version}",
        f"- **Message type**: {readiness.message_type or 'unknown'}",
        f"- **Readiness score**: {readiness.readiness_score}/100 "
        f"(grade {pack.grade})",
        f"- **Structurally valid**: {'yes' if readiness.is_valid else 'no'}",
        f"- **Seal**: `{pack.digest or 'unsealed'}`",
    ]
    if pack.metadata:
        lines.append("")
        lines.append("## Audit metadata")
        lines += [
            f"- **{key}**: {value}"
            for key, value in sorted(pack.metadata.items())
        ]

    lines.append("")
    lines.append("## Structural errors")
    lines += _finding_lines(readiness.structural_errors) or [
        "- None.",
    ]

    lines.append("")
    lines.append("## Profile findings")
    lines += _finding_lines(readiness.profile_findings) or [
        "- None.",
    ]

    if pack.remediation is not None:
        remediation = pack.remediation
        applied = "yes" if remediation.remediation_applied else "no"
        lines.append("")
        lines.append("## Remediation")
        lines.append(f"- **Applied**: {applied}")
        for fix in remediation.fixes_log:
            lines.append(f"- Fix: {fix}")
        if remediation.residual_findings:
            lines.append("- Residual findings:")
            lines += [
                f"  {line}"
                for line in _finding_lines(remediation.residual_findings)
            ]

    if pack.simulated_responses:
        lines.append("")
        lines.append("## Simulated bank responses")
        lines += [
            f"- `{r.status}` via `{r.generated_response_type}`"
            for r in pack.simulated_responses
        ]

    lines.append("")
    return "\n".join(lines)
