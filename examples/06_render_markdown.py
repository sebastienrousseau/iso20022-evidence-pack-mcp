#!/usr/bin/env python3
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

"""Example: render a pack as a markdown compliance report.

:func:`render_markdown` turns a sealed pack into a human-readable summary
suitable for an audit appendix — metadata, findings, remediation, and any
simulated bank responses.

Usage::

    python examples/06_render_markdown.py
"""

import json

from iso20022_evidence_pack_mcp.server import (
    build_evidence_pack,
    render_markdown,
)

_READINESS = {
    "message_type": "pain.001.001.09",
    "is_valid": True,
    "readiness_score": 82,
    "structural_errors": [
        {"code": "EP_STRUCT_1", "explanation": "Missing element."}
    ],
}
_METADATA = {"institution": "Acme Bank", "reference": "AUDIT-2026-01"}


def main() -> None:
    """Build a pack and print its rendered markdown report."""
    built = build_evidence_pack(
        readiness_content=json.dumps(_READINESS), metadata=_METADATA
    )
    pack_json = json.dumps(built["pack"])
    result = render_markdown(pack_content=pack_json)
    print(result["markdown"])


if __name__ == "__main__":
    main()
