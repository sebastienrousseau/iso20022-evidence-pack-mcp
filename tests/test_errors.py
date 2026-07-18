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

"""The error taxonomy: stable codes and serializable ``to_detail`` output."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from iso20022_evidence_pack_mcp.errors import (
    ErrorDetail,
    EvidencePackError,
    InvalidInputError,
    SealMismatchError,
)


@pytest.mark.parametrize(
    ("cls", "code"),
    [
        (EvidencePackError, "EP_ERROR"),
        (InvalidInputError, "EP_INVALID_INPUT"),
        (SealMismatchError, "EP_SEAL_MISMATCH"),
    ],
)
def test_subclass_code_and_to_detail(
    cls: type[EvidencePackError], code: str
) -> None:
    """Each error carries its code through to a serializable detail."""
    exc = cls("boom", locator="/here", context={"k": "v"})
    detail = exc.to_detail()
    assert isinstance(detail, ErrorDetail)
    assert detail.code == code
    assert detail.locator == "/here"
    assert detail.explanation == "boom"
    assert detail.context == {"k": "v"}


def test_error_defaults() -> None:
    """Locator defaults to ``/`` and context to an empty dict."""
    exc = EvidencePackError("nope")
    assert exc.locator == "/"
    assert exc.context == {}
    assert str(exc) == "nope"


def test_subclasses_are_evidence_pack_errors() -> None:
    """Both concrete errors specialise :class:`EvidencePackError`."""
    assert issubclass(InvalidInputError, EvidencePackError)
    assert issubclass(SealMismatchError, EvidencePackError)


def test_error_detail_defaults() -> None:
    """A bare :class:`ErrorDetail` defaults its locator and context."""
    detail = ErrorDetail(code="X", explanation="e")
    assert detail.locator == "/"
    assert detail.context == {}


def test_error_detail_is_frozen() -> None:
    """:class:`ErrorDetail` is immutable once constructed."""
    detail = ErrorDetail(code="X", explanation="e")
    with pytest.raises(ValidationError):
        detail.code = "Y"  # type: ignore[misc]
