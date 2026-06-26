"""Azure Service Bus publisher — CloudEvents 1.0 envelope over Service Bus.

ServiceBusPublisher is the only outbound adapter the agent handlers interact
with.  It manages a single ServiceBusClient and caches one sender per queue,
so callers never deal with SDK lifecycle details.

Authentication:
- Production: pass fully_qualified_namespace + an AsyncTokenCredential
  (ManagedIdentity / WorkloadIdentity from the platform provider).
- Tests: pass connection_string (Service Bus emulator or Azurite).

Exactly one of (fully_qualified_namespace + credential) OR connection_string
must be provided.
"""

from __future__ import annotations

from typing import Any

from azure.servicebus import ServiceBusMessage
from azure.servicebus.aio import ServiceBusClient, ServiceBusSender
from azure.servicebus.exceptions import ServiceBusError

from waf_shared.domain.errors.infrastructure_errors import ServiceBusDeliveryError
from waf_shared.domain.events.base import CloudEventEnvelope
from waf_shared.telemetry.logging import StructuredLogger

_CONTENT_TYPE = "application/cloudevents+json; charset=utf-8"


class ServiceBusPublisher:
    """Sends CloudEventEnvelope messages to Azure Service Bus queues.

    Thread-safety: intended for use within a single asyncio event loop.
    Do not share instances across loops.
    """

    def __init__(
        self,
        *,
        fully_qualified_namespace: str | None = None,
        credential: Any | None = None,
        connection_string: str | None = None,
        logger: StructuredLogger | None = None,
    ) -> None:
        if connection_string is None and (fully_qualified_namespace is None or credential is None):
            raise ValueError(
                "Provide either connection_string OR (fully_qualified_namespace AND credential)"
            )
        self._namespace = fully_qualified_namespace
        self._credential = credential
        self._connection_string = connection_string
        self._logger = logger or StructuredLogger(service="waf-shared", version="0.1.0")
        self._client: ServiceBusClient | None = None
        self._senders: dict[str, ServiceBusSender] = {}

    async def _ensure_client(self) -> ServiceBusClient:
        if self._client is None:
            if self._connection_string is not None:
                self._client = ServiceBusClient.from_connection_string(self._connection_string)
            else:
                self._client = ServiceBusClient(
                    fully_qualified_namespace=self._namespace,
                    credential=self._credential,
                )
        return self._client

    async def _get_sender(self, queue_name: str) -> ServiceBusSender:
        if queue_name not in self._senders:
            client = await self._ensure_client()
            sender = client.get_queue_sender(queue_name=queue_name)
            self._senders[queue_name] = sender
        return self._senders[queue_name]

    async def publish(
        self,
        queue_name: str,
        envelope: CloudEventEnvelope[Any],
    ) -> None:
        """Serialize envelope as CloudEvents JSON and send to the given queue."""
        sender = await self._get_sender(queue_name)
        body = envelope.to_json_bytes()
        msg = ServiceBusMessage(
            body=body,
            content_type=_CONTENT_TYPE,
            message_id=str(envelope.id),
        )
        try:
            await sender.send_messages(msg)
            self._logger.debug(
                "servicebus.publisher.sent",
                queue=queue_name,
                event_type=envelope.type,
                message_id=str(envelope.id),
            )
        except ServiceBusError as exc:
            raise ServiceBusDeliveryError(queue_name=queue_name, reason=str(exc)) from exc

    async def close(self) -> None:
        """Close all senders and the underlying client connection."""
        for sender in self._senders.values():
            try:
                await sender.close()
            except Exception:
                pass
        self._senders.clear()
        if self._client is not None:
            try:
                await self._client.close()
            except Exception:
                pass
            self._client = None
