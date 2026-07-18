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

"""Example: show the readiness-score grade bands.

A pack's grade is derived from its readiness score: A (>= 90), B (>= 75),
C (>= 50), otherwise F. This walks a few representative scores through
:func:`grade`.

Usage::

    python examples/07_grade_bands.py
"""

from iso20022_evidence_pack_mcp.builder import grade

_SCORES = [100, 90, 89, 75, 74, 50, 49, 0]


def main() -> None:
    """Print the grade for each representative readiness score."""
    print("score  grade")
    print("-----  -----")
    for score in _SCORES:
        print(f"{score:>5}    {grade(score)}")


if __name__ == "__main__":
    main()
