# Quickstart

A 10-minute install → MCP client config → first sealed pack tutorial for
`iso20022-evidence-pack-mcp`, the audit and certification server of the
ISO 20022 MCP Suite.

## 1. Install

`iso20022-evidence-pack-mcp` runs on macOS, Linux, and Windows and requires
Python 3.10+. It pulls in only the MCP SDK and `pydantic` — there are no other
runtime dependencies.

```sh
python -m pip install iso20022-evidence-pack-mcp
```

Verify:

```sh
python -c "import iso20022_evidence_pack_mcp; print(iso20022_evidence_pack_mcp.__version__)"
```

This server is fully local and closed-world: no network, no sub-servers, no
XML. Nothing else needs to be installed.

## 2. Launch the server

The package installs an `iso20022-evidence-pack-mcp` console entry point that
starts the server over stdio (FastMCP's default transport):

```sh
iso20022-evidence-pack-mcp
```

The command speaks MCP on stdin/stdout — it is meant to be launched by an MCP
client, not used interactively. (`iso20022-evidence-pack-mcp --version` prints
the version and exits.)

## 3. Register it with your MCP client

### Claude Desktop

Add an entry to `~/Library/Application Support/Claude/claude_desktop_config.json`
(macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "iso20022-evidence-pack": { "command": "iso20022-evidence-pack-mcp" }
  }
}
```

Restart Claude Desktop. The 4 tools are now available in any chat.

### Other clients (Cursor, Continue, generic stdio MCP clients)

Point the client at the `iso20022-evidence-pack-mcp` command. The server speaks
standard MCP — no custom transport, no auth. If the entry point is not on the
client's `PATH` (GUI apps often have a minimal `PATH`), use the absolute path
from `which iso20022-evidence-pack-mcp` in the `command` field.

## 4. First conversation

Hand the agent a readiness result (from `iso20022-readiness-suite-mcp`, or any
JSON of the same shape) and ask it to seal an evidence pack:

> Here is the readiness result for our pacs.008 batch. Build a sealed evidence
> pack from it, tell me the grade and the digest, then verify the seal and
> render the compliance report.

A typical flow: the agent calls `build_evidence_pack` to fold the readiness
result (and any remediation / simulation JSON) into a graded, sealed pack;
`verify_seal` to confirm the digest round-trips; and `render_markdown` to
produce the report.

## 5. Use in-process (no MCP client needed)

To prototype or write integration tests, call the tools through the FastMCP
instance directly:

```python
import asyncio
import json

from iso20022_evidence_pack_mcp import server


async def main() -> None:
    async def call(name, args):
        result = await server.server.call_tool(name, args)
        content = result[0] if isinstance(result, tuple) else result
        return content[0].text if content else ""

    readiness = json.dumps({
        "message_type": "pacs.008.001.08",
        "is_valid": True,
        "readiness_score": 92,
    })
    built = json.loads(await call("build_evidence_pack",
                                  {"readiness_content": readiness}))
    print(built["pack"]["grade"], built["digest"])  # -> A sha256:...


asyncio.run(main())
```

## 6. The 4 tools at a glance

| Tool | What it does |
| --- | --- |
| `build_evidence_pack` | Fold readiness (+ optional remediation, simulation, metadata) into a graded, sealed pack; returns the pack, its digest, and a markdown report |
| `seal_pack` | Compute the deterministic SHA-256 seal for a pack |
| `verify_seal` | Recompute a pack's seal and compare it to an expected digest |
| `render_markdown` | Render a pack as a markdown compliance report |

`build_evidence_pack` requires a `readiness_content` JSON string; the
`remediation_content`, `simulation_content`, and `metadata` inputs are
optional. `verify_seal` also takes the `expected_digest` to check against.

## 7. Next steps

- Read [`evidence-packs.md`](evidence-packs.md) for the pack schema, the
  sealing model, and the readiness → evidence pipeline.
- Browse the full [tool catalog](https://github.com/sebastienrousseau/iso20022-evidence-pack-mcp/blob/main/README.md#tools).
- Run the [examples](https://github.com/sebastienrousseau/iso20022-evidence-pack-mcp/blob/main/examples/README.md).

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `command not found: iso20022-evidence-pack-mcp` | Install went to a venv that isn't on PATH | Re-install in your active env, or invoke `python -m iso20022_evidence_pack_mcp.server` |
| MCP client doesn't see the tools | Wrong path in client config | Use an absolute path: `which iso20022-evidence-pack-mcp` → paste into the client `command` |
| `build_evidence_pack` returns an `{"error": ...}` | The `readiness_content` was not valid JSON or not a JSON object | Pass a JSON object string (e.g. `{"readiness_score": 92, ...}`) |
| `verify_seal` returns `verified: false` | The pack changed since it was sealed, or the wrong digest was supplied | Re-seal the current pack with `seal_pack` and compare, or check you passed the digest that matches this pack |
