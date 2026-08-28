#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""What an evidence pack costs to build, seal, verify and render.

A pack is the artefact an institution keeps. It grows with the number of
findings a readiness run produced, and a real migration produces thousands,
not the handful in the fixtures. Every stage here therefore gets measured
against finding count rather than at one size.

What each stage is watched for:

* **``build_evidence_pack``** — should be linear in findings. It assembles
  a document; if the cost curves upward, something is re-serialising or
  re-scanning what it has already placed.

* **``seal_pack`` and ``verify_seal``** — a digest over the canonical form.
  These should be *fast* and linear, and **verify should cost about the
  same as seal**: both hash the same bytes. Verification costing markedly
  more would mean it is rebuilding something instead of hashing what it
  was given.

* **The tamper path.** ``verify_seal`` against a modified pack must not be
  cheaper than against a good one. A short-circuit that bails early on a
  mismatched prefix turns the digest check into a timing oracle — it tells
  an attacker how much of a forged pack was accepted before the difference
  was found. Equal cost is the property worth holding, and nothing was
  measuring it.

Run::

    python benches/bench_pack_lifecycle.py
    python benches/bench_pack_lifecycle.py --json
    python benches/bench_pack_lifecycle.py --quick     # what CI runs

Nothing here asserts a threshold: wall-clock is not comparable between
machines, and a flaky performance gate teaches people to ignore red. CI
runs ``--quick`` so a benchmark that has stopped compiling against the
current API fails the build instead of rotting into a file that reads as
verified and is not.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from iso20022_evidence_pack_mcp import server  # noqa: E402


def readiness(findings: int) -> str:
    """A readiness result carrying ``findings`` profile findings."""
    return json.dumps(
        {
            "message_type": "pain.001.001.09",
            "is_valid": False,
            "readiness_score": 72,
            "profile_findings": [
                {
                    "code": "CBPR_ADDR",
                    "locator": f"/PmtInf[{i}]/Cdtr/PstlAdr",
                    "explanation": "Address not fully structured.",
                    "context": {"severity": "warning"},
                }
                for i in range(findings)
            ],
        }
    )


def _best(call, repeats: int) -> float:
    """Best-of timing after one untimed warm-up.

    The minimum is the least noisy estimator here; the mean follows
    whatever else the machine is doing.
    """
    call()
    samples = []
    for _ in range(repeats):
        start = time.perf_counter()
        call()
        samples.append(time.perf_counter() - start)
    return min(samples)


def measure(findings: int, repeats: int) -> dict:
    """One pack through its whole lifecycle."""
    source = readiness(findings)

    build = _best(lambda: server.build_evidence_pack(source), repeats)
    pack = json.dumps(server.build_evidence_pack(source))

    seal = _best(lambda: server.seal_pack(pack), repeats)
    digest = server.seal_pack(pack)["digest"]

    verify = _best(lambda: server.verify_seal(pack, digest), repeats)

    # The same pack with one character changed. Verification must cost the
    # same as the good case; cheaper means an early bail-out.
    tampered = pack.replace("CBPR_ADDR", "CBPR_ADDX", 1)
    tamper = _best(lambda: server.verify_seal(tampered, digest), repeats)

    render = _best(lambda: server.render_markdown(pack), repeats)

    return {
        "findings": findings,
        "pack_kib": len(pack) / 1024,
        "build_ms": build * 1e3,
        "seal_ms": seal * 1e3,
        "verify_ms": verify * 1e3,
        "tamper_ms": tamper * 1e3,
        "render_ms": render * 1e3,
        "build_us_per_finding": build * 1e6 / findings,
        "tamper_over_verify": tamper / verify if verify else 0.0,
    }


def run(quick: bool) -> list[dict]:
    sizes = [10, 100] if quick else [10, 100, 1_000, 5_000]
    repeats = 3 if quick else 7
    return [measure(n, repeats) for n in sizes]


def render_table(rows: list[dict]) -> None:
    print(
        f"{'findings':>9}{'pack KiB':>10}{'build ms':>10}{'seal ms':>9}"
        f"{'verify ms':>11}{'render ms':>11}{'us/finding':>12}"
    )
    for row in rows:
        print(
            f"{row['findings']:>9}{row['pack_kib']:>10.1f}"
            f"{row['build_ms']:>10.2f}{row['seal_ms']:>9.3f}"
            f"{row['verify_ms']:>11.3f}{row['render_ms']:>11.3f}"
            f"{row['build_us_per_finding']:>12.1f}"
        )
    if len(rows) >= 2 and rows[0]["build_us_per_finding"]:
        drift = (
            rows[-1]["build_us_per_finding"] / rows[0]["build_us_per_finding"]
        )
        print(
            f"\n  build us/finding at {rows[-1]['findings']:,} is "
            f"{drift:.2f}x the cost at {rows[0]['findings']:,}. Flat is "
            f"linear; climbing means something is re-serialising what it "
            f"has already placed."
        )

    print("\ntamper detection — verifying a modified pack")
    print(f"{'findings':>9}{'good ms':>10}{'tampered ms':>13}{'ratio':>8}")
    for row in rows:
        print(
            f"{row['findings']:>9}{row['verify_ms']:>10.3f}"
            f"{row['tamper_ms']:>13.3f}{row['tamper_over_verify']:>8.2f}"
        )
    print(
        "  The ratio should sit near 1.00. Markedly below it means\n"
        "  verification bails out early on a mismatch, which turns the\n"
        "  digest check into a timing oracle: it tells an attacker how much\n"
        "  of a forged pack was accepted before the difference was found.\n"
        "\n"
        "  Read it across runs, not from one. These are sub-millisecond\n"
        "  measurements, so a single row can land anywhere between roughly\n"
        "  0.6 and 1.2 on an otherwise idle machine. One low reading is\n"
        "  noise; a ratio that stays low across several runs, and stays low\n"
        "  as findings grow, is the thing worth investigating."
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument(
        "--quick", action="store_true", help="small sizes, as CI runs"
    )
    args = parser.parse_args()

    rows = run(quick=args.quick)
    if args.json:
        json.dump(rows, sys.stdout, indent=1)
        print()
    else:
        render_table(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
