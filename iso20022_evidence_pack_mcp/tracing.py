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

"""Opt-in OpenTelemetry tracing for the evidence-pack server.

Tracing is **off by default** and gated behind the optional ``[otel]`` extra,
mirroring the closed-world / lazy-import discipline of
:mod:`iso20022_evidence_pack_mcp.cloud`. Importing this module never pulls in
``opentelemetry``; the SDK is imported lazily inside :func:`init_tracing`.

When the extra is absent, :func:`init_tracing` returns ``False`` and every span
helper degrades to a no-op -- tracing never raises across a tool boundary and
never changes a tool's output, consistent with the server's
"data-not-tracebacks" paradigm. Activate it with either ``--otel-endpoint`` or
the standard ``OTEL_EXPORTER_OTLP_ENDPOINT`` environment variable.
"""

from __future__ import annotations

import functools
import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, TypeVar, cast

if TYPE_CHECKING:
    from opentelemetry.trace import Tracer

#: Default resource ``service.name`` reported to the collector.
DEFAULT_SERVICE_NAME = "iso20022-evidence-pack-mcp"

#: Standard OTLP endpoint variable honoured when no explicit endpoint is given.
OTEL_ENDPOINT_ENV = "OTEL_EXPORTER_OTLP_ENDPOINT"

#: Process-global tracer, set by :func:`init_tracing`. ``None`` means tracing
#: is inactive and every span helper degrades to a no-op.
_tracer: Tracer | None = None

F = TypeVar("F", bound=Callable[..., Any])


def init_tracing(
    endpoint: str | None = None,
    service_name: str = DEFAULT_SERVICE_NAME,
) -> bool:
    """Initialise OpenTelemetry tracing for the process.

    Lazily imports the OpenTelemetry SDK. When the ``[otel]`` extra is not
    installed the import fails and this returns ``False`` without raising, so
    the caller can offer tracing as a best-effort opt-in. Otherwise it builds a
    ``TracerProvider`` carrying a ``service.name`` resource, attaches an OTLP
    (HTTP) ``BatchSpanProcessor`` when an endpoint is configured (via the
    ``endpoint`` argument or ``OTEL_EXPORTER_OTLP_ENDPOINT``), records the
    tracer process-globally, and returns ``True``.

    Args:
        endpoint: An explicit OTLP/HTTP collector endpoint. When omitted, the
            ``OTEL_EXPORTER_OTLP_ENDPOINT`` environment variable is consulted.
            With no endpoint, spans are produced but not exported (useful for
            in-process instrumentation or a later processor).
        service_name: The ``service.name`` reported on the resource.

    Returns:
        ``True`` when tracing was initialised; ``False`` when the ``[otel]``
        extra is not installed.
    """
    global _tracer
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        return False

    resource = Resource.create({"service.name": service_name})
    provider = TracerProvider(resource=resource)

    endpoint = endpoint or os.environ.get(OTEL_ENDPOINT_ENV)
    if endpoint:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )

        provider.add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint))
        )

    trace.set_tracer_provider(provider)
    # Take the tracer from the provider we just built, not the global default:
    # OpenTelemetry ignores a second ``set_tracer_provider`` call, so binding
    # to our own provider keeps behaviour deterministic across re-inits.
    _tracer = provider.get_tracer(DEFAULT_SERVICE_NAME)
    return True


def is_active() -> bool:
    """Return whether tracing has been initialised for this process."""
    return _tracer is not None


@contextmanager
def trace_span(name: str) -> Iterator[None]:
    """Span an operation, recording any exception and error status.

    A no-op when tracing is inactive (:func:`init_tracing` never ran or the
    ``[otel]`` extra is absent): the body runs untouched and no span is
    emitted. When active, a span named ``name`` wraps the body; a raised
    exception is recorded on the span and the span status is set to ``ERROR``
    before the exception is re-raised unchanged, so tracing never swallows or
    alters an error.

    Args:
        name: The span name (typically the tool being invoked).
    """
    tracer = _tracer
    if tracer is None:
        yield
        return

    from opentelemetry.trace import Status, StatusCode

    with tracer.start_as_current_span(name) as span:
        try:
            yield
        except Exception as exc:
            span.record_exception(exc)
            span.set_status(Status(StatusCode.ERROR, str(exc)))
            raise
        else:
            span.set_status(Status(StatusCode.OK))


def traced_tool(name: str) -> Callable[[F], F]:
    """Decorate a callable so each invocation runs inside a :func:`trace_span`.

    A no-op wrapper when tracing is inactive, so it is safe to apply
    unconditionally at import time. The wrapped callable's signature, docstring,
    and annotations are preserved (via :func:`functools.wraps`), so tool schema
    introspection is unaffected and outputs are unchanged.

    Args:
        name: The span name to open around each call.
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            with trace_span(name):
                return func(*args, **kwargs)

        return cast(F, wrapper)

    return decorator
