"""Blob Storage uploader — uploads report files and returns blob paths only.

Uploads Excel and PDF to Azure Blob Storage using Managed Identity
(Storage Blob Data Contributor role on the container).

Security contract:
  - Never store SAS URLs in the database.
  - Return the blob path only (e.g. "reports/{tenant_id}/{assessment_id}/report.xlsx").
  - SAS tokens are generated on-demand by the API tier with a ≤ 15-minute TTL.

The caller passes a BlobServiceClient already authenticated with the platform
credential — no connection strings or storage account keys in this module.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

from waf_shared.domain.errors.infrastructure_errors import InfrastructureError
from waf_shared.telemetry.logging import StructuredLogger

_BLOB_PATH_TEMPLATE = "reports/{tenant_id}/{assessment_id}/report.{ext}"


class StorageUploadError(InfrastructureError):
    def __init__(self, blob_path: str, reason: str) -> None:
        super().__init__(
            f"Failed to upload blob '{blob_path}': {reason}",
            code="STORAGE_UPLOAD_ERROR",
        )
        self.blob_path = blob_path
        self.reason = reason


class StorageUploader:
    """Uploads report bytes to Azure Blob Storage; returns the blob path (never SAS)."""

    def __init__(
        self,
        blob_service_client: Any = None,
        container_name: str = "reports",
        logger: StructuredLogger | None = None,
        blob_service: Any = None,
    ) -> None:
        self._blob_service = blob_service_client or blob_service
        self._container_name = container_name
        self._logger = logger or StructuredLogger(service="waf-reporting.storage", version="0.1.0")

    async def upload_report(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
        content: bytes | None = None,
        extension: str = "",
        content_type: str | None = None,
        data: bytes | None = None,
    ) -> str:
        """Upload report bytes and return the blob path (not a SAS URL)."""
        _bytes = content if content is not None else data
        if _bytes is None:
            blob_path = _BLOB_PATH_TEMPLATE.format(
                tenant_id=tenant_id, assessment_id=assessment_id, ext=extension
            )
            raise StorageUploadError(blob_path, "no content provided")
        blob_path = _BLOB_PATH_TEMPLATE.format(
            tenant_id=tenant_id,
            assessment_id=assessment_id,
            ext=extension,
        )
        log = self._logger.bind(
            blob_path=blob_path,
            size_bytes=len(_bytes) if _bytes else 0,
        )
        try:
            container_client = self._blob_service.get_container_client(self._container_name)
            upload_fn = container_client.upload_blob
            if asyncio.iscoroutinefunction(upload_fn):
                await upload_fn(blob_path, _bytes, overwrite=True)
            else:
                blob_client = container_client.get_blob_client(blob_path)
                await blob_client.upload_blob(_bytes, overwrite=True)
            log.info("reporting.storage.uploaded")
            return blob_path
        except StorageUploadError:
            raise
        except Exception as exc:
            log.error("reporting.storage.upload_failed", exc_info=True)
            raise StorageUploadError(blob_path, "upload failed") from exc
