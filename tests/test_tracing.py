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

"""Opt-in OpenTelemetry tracing.

Spans are captured with an in-memory exporter (nothing leaves the process); the
missing-``[otel]``-extra path is simulated by making the lazy ``opentelemetry``
import raise ``ImportError``. The tests assert span emission, exception/status
recording, and the graceful no-op behaviour when tracing is inactive.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)
from opentelemetry.trace import StatusCode

from iso20022_evidence_pack_mcp import tracing


@pytest.fixture(autouse=True)
def _reset_tracer() -> Iterator[None]:
    """Isolate the process-global tracer around every test."""
    saved = tracing._tracer
    yield
    tracing._tracer = saved


@pytest.fixture
def exporter() -> InMemorySpanExporter:
    """Bind ``tracing._tracer`` to a tracer feeding an in-memory exporter."""
    memory = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(memory))
    tracing._tracer = provider.get_tracer("test")
    return memory


# --------------------------------------------------------------------------
# init_tracing
# --------------------------------------------------------------------------


def test_init_tracing_without_endpoint_activates() -> None:
    """``init_tracing()`` with no endpoint activates tracing, no exporter."""
    assert not tracing.is_active()
    assert tracing.init_tracing(service_name="unit-test") is True
    assert tracing.is_active()


def test_init_tracing_with_endpoint_attaches_otlp() -> None:
    """An explicit endpoint wires an OTLP batch processor and activates."""
    assert (
        tracing.init_tracing(endpoint="http://localhost:4318/v1/traces")
        is True
    )
    assert tracing.is_active()


def test_init_tracing_honours_endpoint_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The OTLP endpoint env var is consulted when no endpoint is passed."""
    monkeypatch.setenv(
        tracing.OTEL_ENDPOINT_ENV, "http://localhost:4318/v1/traces"
    )
    assert tracing.init_tracing() is True
    assert tracing.is_active()


def test_init_tracing_missing_extra_returns_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the [otel] extra is absent, init returns False and stays inactive."""
    monkeypatch.setitem(sys.modules, "opentelemetry", None)
    assert tracing.init_tracing() is False
    assert not tracing.is_active()


# --------------------------------------------------------------------------
# trace_span / traced_tool
# --------------------------------------------------------------------------


def test_trace_span_noop_when_inactive() -> None:
    """With tracing inactive, ``trace_span`` runs the body and emits nothing."""
    tracing._tracer = None
    ran: list[int] = []
    with tracing.trace_span("noop"):
        ran.append(1)
    assert ran == [1]


def test_trace_span_records_success(
    exporter: InMemorySpanExporter,
) -> None:
    """A successful span is exported with OK status."""
    with tracing.trace_span("do-work"):
        pass
    spans = exporter.get_finished_spans()
    assert [s.name for s in spans] == ["do-work"]
    assert spans[0].status.status_code == StatusCode.OK


def test_trace_span_records_exception(
    exporter: InMemorySpanExporter,
) -> None:
    """A raised exception is recorded on the span, then re-raised unchanged."""
    with pytest.raises(ValueError, match="boom"):
        with tracing.trace_span("do-work"):
            raise ValueError("boom")
    spans = exporter.get_finished_spans()
    assert spans[0].status.status_code == StatusCode.ERROR
    assert any(e.name == "exception" for e in spans[0].events)


def test_traced_tool_wraps_and_preserves_metadata(
    exporter: InMemorySpanExporter,
) -> None:
    """``traced_tool`` spans the call and preserves the wrapped signature."""

    @tracing.traced_tool("compute")
    def compute(value: int) -> int:
        """Double a value."""
        return value * 2

    assert compute(21) == 42
    assert compute.__name__ == "compute"
    assert compute.__doc__ == "Double a value."
    spans = exporter.get_finished_spans()
    assert [s.name for s in spans] == ["compute"]
