"""OpenTelemetry SDK configuration — TracerProvider + MeterProvider → Azure Monitor."""

from __future__ import annotations

import os

from opentelemetry import metrics, trace
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor


def configure_telemetry(
    service_name: str,
    service_version: str,
    connection_string: str | None = None,
    enabled: bool = True,
) -> None:
    resource = Resource.create(
        {
            "service.name": service_name,
            "service.version": service_version,
        }
    )

    if not enabled or not connection_string:
        _configure_noop(resource)
        return

    _configure_azure_monitor(resource, connection_string)


def _configure_noop(resource: Resource) -> None:
    tracer_provider = TracerProvider(resource=resource)
    trace.set_tracer_provider(tracer_provider)

    meter_provider = MeterProvider(resource=resource)
    metrics.set_meter_provider(meter_provider)


def _configure_azure_monitor(resource: Resource, connection_string: str) -> None:
    try:
        from azure.monitor.opentelemetry.exporter import (
            AzureMonitorMetricExporter,
            AzureMonitorTraceExporter,
        )
    except ImportError as exc:
        raise RuntimeError(
            "azure-monitor-opentelemetry-exporter is required for production telemetry"
        ) from exc

    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(
        BatchSpanProcessor(AzureMonitorTraceExporter(connection_string=connection_string))
    )
    trace.set_tracer_provider(tracer_provider)

    reader = PeriodicExportingMetricReader(
        AzureMonitorMetricExporter(connection_string=connection_string),
        export_interval_millis=60_000,
    )
    meter_provider = MeterProvider(resource=resource, metric_readers=[reader])
    metrics.set_meter_provider(meter_provider)


def get_tracer(name: str) -> trace.Tracer:
    return trace.get_tracer(name)


def get_meter(name: str) -> metrics.Meter:
    return metrics.get_meter(name)
