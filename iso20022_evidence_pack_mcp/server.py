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

"""Model Context Protocol (MCP) server for ISO 20022 evidence packs.

This server compiles a readiness result, an optional remediation result, and
any simulated bank responses into one sealed, exportable audit artifact, and
lets auditors re-seal, verify, and render packs. It is a fully local, closed-
world server (no network surface, no sub-servers): every tool returns typed,
JSON-serializable data and an ``{"error": ...}``-shaped payload on any failure,
never a traceback.

Launch as a console script (``iso20022-evidence-pack-mcp``) or configure it in
an MCP client. The transport is stdio (FastMCP's default).
"""

from __future__ import annotations

import argparse
import json
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from iso20022_evidence_pack_mcp import __version__, builder, report
from iso20022_evidence_pack_mcp.errors import (
    ErrorDetail,
    EvidencePackError,
    InvalidInputError,
)
from iso20022_evidence_pack_mcp.models import (
    BuildRequest,
    BuildResponse,
    RenderRequest,
    RenderResponse,
    SealRequest,
    SealResponse,
    VerifyRequest,
    VerifyResponse,
)

server = FastMCP("iso20022-evidence-pack")
# FastMCP does not accept a version kwarg; set it so serverInfo.version is
# coherent with the package version.
server._mcp_server.version = __version__

# Every tool is a pure, local, deterministic, closed-world transform.
_LOCAL = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)


def _as_detail(exc: Exception) -> ErrorDetail:
    """Render any exception as a serializable :class:`ErrorDetail`."""
    if isinstance(exc, EvidencePackError):
        return exc.to_detail()
    return ErrorDetail(code="EP_ERROR", explanation=f"Unexpected error: {exc}")


def _loads(content: str, locator: str) -> Any:
    """Parse raw JSON text, raising :class:`InvalidInputError` on failure."""
    try:
        return json.loads(content)
    except json.JSONDecodeError as exc:
        raise InvalidInputError(
            f"{locator} is not valid JSON: {exc}", locator=locator
        ) from exc


@server.tool(title="Build an evidence pack", annotations=_LOCAL)
def build_evidence_pack(
    readiness_content: Annotated[
        str, Field(description="A readiness result as raw JSON text.")
    ],
    remediation_content: Annotated[
        str | None,
        Field(default=None, description="Optional remediation JSON text."),
    ] = None,
    simulation_content: Annotated[
        str | None,
        Field(default=None, description="Optional simulated-responses JSON."),
    ] = None,
    metadata: Annotated[
        dict[str, str] | None,
        Field(default=None, description="Free-form audit metadata."),
    ] = None,
) -> dict[str, Any]:
    """Fold readiness, remediation, and simulations into a sealed pack.

    Args:
        readiness_content: A readiness result, as JSON text.
        remediation_content: An optional remediation result, as JSON text.
        simulation_content: An optional JSON array of simulated responses.
        metadata: Free-form audit metadata (institution, reference, ...).
    """
    request = BuildRequest(
        readiness_content=readiness_content,
        remediation_content=remediation_content,
        simulation_content=simulation_content,
        metadata=metadata or {},
    )
    try:
        readiness = _loads(request.readiness_content, "/readiness_content")
        remediation = (
            _loads(request.remediation_content, "/remediation_content")
            if request.remediation_content is not None
            else None
        )
        simulation = (
            _loads(request.simulation_content, "/simulation_content")
            if request.simulation_content is not None
            else None
        )
        pack = builder.build_pack(
            readiness, remediation, simulation, request.metadata
        )
        response = BuildResponse(
            pack=pack,
            digest=pack.digest,
            markdown=report.render_markdown(pack),
        )
    except Exception as exc:  # noqa: BLE001 - boundary: return data, not trace
        response = BuildResponse(error=_as_detail(exc))
    return response.model_dump(mode="json")


@server.tool(title="Seal an evidence pack", annotations=_LOCAL)
def seal_pack(
    pack_content: Annotated[
        str, Field(description="An evidence pack as raw JSON text.")
    ],
) -> dict[str, Any]:
    """Compute the deterministic SHA-256 seal for an evidence pack.

    Args:
        pack_content: The evidence pack to seal, as JSON text.
    """
    request = SealRequest(pack_content=pack_content)
    try:
        pack = builder.parse_pack(request.pack_content)
        response = SealResponse(digest=builder.compute_digest(pack))
    except Exception as exc:  # noqa: BLE001 - boundary: return data, not trace
        response = SealResponse(error=_as_detail(exc))
    return response.model_dump(mode="json")


@server.tool(title="Verify an evidence-pack seal", annotations=_LOCAL)
def verify_seal(
    pack_content: Annotated[
        str, Field(description="An evidence pack as raw JSON text.")
    ],
    expected_digest: Annotated[
        str, Field(description="The seal to check the pack against.")
    ],
) -> dict[str, Any]:
    """Recompute a pack's seal and compare it to an expected digest.

    Args:
        pack_content: The evidence pack to check, as JSON text.
        expected_digest: The seal the pack is expected to carry.
    """
    request = VerifyRequest(
        pack_content=pack_content, expected_digest=expected_digest
    )
    try:
        pack = builder.parse_pack(request.pack_content)
        computed = builder.compute_digest(pack)
        response = VerifyResponse(
            verified=computed == request.expected_digest,
            computed_digest=computed,
        )
    except Exception as exc:  # noqa: BLE001 - boundary: return data, not trace
        response = VerifyResponse(error=_as_detail(exc))
    return response.model_dump(mode="json")


@server.tool(title="Render an evidence pack", annotations=_LOCAL)
def render_markdown(
    pack_content: Annotated[
        str, Field(description="An evidence pack as raw JSON text.")
    ],
) -> dict[str, Any]:
    """Render an evidence pack as a markdown compliance report.

    Args:
        pack_content: The evidence pack to render, as JSON text.
    """
    request = RenderRequest(pack_content=pack_content)
    try:
        pack = builder.parse_pack(request.pack_content)
        response = RenderResponse(markdown=report.render_markdown(pack))
    except Exception as exc:  # noqa: BLE001 - boundary: return data, not trace
        response = RenderResponse(error=_as_detail(exc))
    return response.model_dump(mode="json")


def main(argv: list[str] | None = None) -> None:
    """Run the MCP server over stdio."""
    parser = argparse.ArgumentParser(
        prog="iso20022-evidence-pack-mcp",
        description="ISO 20022 evidence-pack MCP server (stdio).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"iso20022-evidence-pack-mcp {__version__}",
    )
    parser.parse_args(argv)
    server.run()


if __name__ == "__main__":  # pragma: no cover
    main()
