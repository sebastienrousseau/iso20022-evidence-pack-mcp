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

"""Per-request tenant and scope context variables."""

from __future__ import annotations

from iso20022_evidence_pack_mcp.http import context


def test_defaults_are_empty() -> None:
    """Outside a request the tenant is ``None`` and scopes are empty."""
    assert context.current_tenant() is None
    assert context.current_scopes() == ()


def test_tenant_set_and_reset() -> None:
    """Setting the tenant var is reflected by :func:`current_tenant`."""
    token = context._tenant_var.set("acme")
    try:
        assert context.current_tenant() == "acme"
    finally:
        context._tenant_var.reset(token)
    assert context.current_tenant() is None


def test_scopes_set_and_reset() -> None:
    """Setting the scopes var is reflected by :func:`current_scopes`."""
    token = context._scopes_var.set(("read", "write"))
    try:
        assert context.current_scopes() == ("read", "write")
    finally:
        context._scopes_var.reset(token)
    assert context.current_scopes() == ()
