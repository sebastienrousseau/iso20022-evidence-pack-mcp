# syntax=docker/dockerfile:1.6
# Multi-stage build for a minimal iso20022-evidence-pack-mcp image.
#
# The container runs the FastMCP evidence-pack server over stdio so an MCP
# client can launch it directly with
# ``docker run -i --rm iso20022-evidence-pack-mcp``.
#
# NOTE: this server is fully local and closed-world. It has no network surface,
# spawns no sub-servers, and parses no XML: every tool works standalone on the
# JSON structures it is handed (a readiness result, optional remediation and
# simulated responses, or an existing pack). Nothing extra needs to be present
# in the runtime environment.

FROM python:3.14-slim@sha256:cae66f2ef0ec51a9891263eeee7f987dacf0a9879e8aa9353d5606e0530619a5 AS builder

WORKDIR /build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# pyproject.toml carries ``readme = "README.md"``, so README.md must be
# present at build-time for ``pip install .`` to resolve the package metadata.
COPY pyproject.toml README.md ./
COPY iso20022_evidence_pack_mcp ./iso20022_evidence_pack_mcp

# Install this package (and its published runtime deps: mcp, pydantic) into a
# self-contained virtualenv.
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install .


FROM python:3.14-slim@sha256:cae66f2ef0ec51a9891263eeee7f987dacf0a9879e8aa9353d5606e0530619a5

LABEL org.opencontainers.image.title="iso20022-evidence-pack-mcp" \
      org.opencontainers.image.description="Local MCP server that seals ISO 20022 readiness evidence into tamper-evident, exportable audit packs." \
      org.opencontainers.image.source="https://github.com/sebastienrousseau/iso20022-evidence-pack-mcp" \
      org.opencontainers.image.licenses="Apache-2.0"

# Non-root user (MCP clients launch the container with stdio; no extra
# privileges needed).
RUN groupadd --system mcp && useradd --system --gid mcp --home /home/mcp mcp \
    && mkdir -p /home/mcp \
    && chown -R mcp:mcp /home/mcp

COPY --from=builder /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER mcp
WORKDIR /home/mcp

# A non-zero exit here means an import / dependency mismatch; the MCP
# client will see it before the first tool call.
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import iso20022_evidence_pack_mcp.server" || exit 1

ENTRYPOINT ["iso20022-evidence-pack-mcp"]
