"""Unit tests for StorageUploader.

Verifies blob path construction, overwrite behaviour, never-a-SAS-URL return
value, and error wrapping.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from waf_reporting.storage_uploader import StorageUploadError, StorageUploader


def _make_uploader() -> tuple[StorageUploader, MagicMock]:
    container_client = AsyncMock()
    container_client.__aenter__ = AsyncMock(return_value=container_client)
    container_client.__aexit__ = AsyncMock(return_value=False)
    container_client.upload_blob = AsyncMock(return_value=MagicMock())

    blob_service = MagicMock()
    blob_service.get_container_client = MagicMock(return_value=container_client)

    uploader = StorageUploader(blob_service_client=blob_service)
    return uploader, container_client


@pytest.mark.unit
class TestStorageUploaderBlobPath:
    async def test_blob_path_format_pdf(self) -> None:
        uploader, container = _make_uploader()
        tid = uuid.uuid4()
        aid = uuid.uuid4()

        path = await uploader.upload_report(
            tenant_id=tid,
            assessment_id=aid,
            content=b"%PDF-1.4 report",
            extension="pdf",
        )

        assert path == f"reports/{tid}/{aid}/report.pdf"
        container.upload_blob.assert_called_once()
        blob_name = container.upload_blob.call_args[0][0]
        assert blob_name == f"reports/{tid}/{aid}/report.pdf"

    async def test_blob_path_format_xlsx(self) -> None:
        uploader, container = _make_uploader()
        tid = uuid.uuid4()
        aid = uuid.uuid4()

        path = await uploader.upload_report(
            tenant_id=tid,
            assessment_id=aid,
            content=b"PK...",
            extension="xlsx",
        )

        assert path == f"reports/{tid}/{aid}/report.xlsx"

    async def test_overwrite_is_true(self) -> None:
        uploader, container = _make_uploader()

        await uploader.upload_report(
            tenant_id=uuid.uuid4(),
            assessment_id=uuid.uuid4(),
            content=b"data",
            extension="pdf",
        )

        call_kwargs = container.upload_blob.call_args[1]
        assert call_kwargs.get("overwrite") is True

    async def test_returns_path_not_sas_url(self) -> None:
        """Critical: returned value must be a path, never a SAS URL."""
        uploader, _ = _make_uploader()

        path = await uploader.upload_report(
            tenant_id=uuid.uuid4(),
            assessment_id=uuid.uuid4(),
            content=b"data",
            extension="pdf",
        )

        assert not path.startswith("https://")
        assert not path.startswith("http://")
        assert "sig=" not in path
        assert "se=" not in path

    async def test_content_passed_to_upload(self) -> None:
        uploader, container = _make_uploader()
        body = b"PDF content bytes"

        await uploader.upload_report(
            tenant_id=uuid.uuid4(),
            assessment_id=uuid.uuid4(),
            content=body,
            extension="pdf",
        )

        data_arg = container.upload_blob.call_args[0][1]
        assert data_arg == body


@pytest.mark.unit
class TestStorageUploaderErrorHandling:
    async def test_storage_error_wrapped_in_storage_upload_error(self) -> None:
        _, container = _make_uploader()
        container.upload_blob = AsyncMock(side_effect=Exception("network timeout"))
        uploader = StorageUploader(blob_service_client=MagicMock(
            get_container_client=MagicMock(return_value=container)
        ))

        with pytest.raises(StorageUploadError) as exc_info:
            await uploader.upload_report(
                tenant_id=uuid.uuid4(),
                assessment_id=uuid.uuid4(),
                content=b"data",
                extension="pdf",
            )

        assert "upload" in str(exc_info.value).lower()

    async def test_error_message_does_not_contain_sas(self) -> None:
        """Error messages must not inadvertently expose SAS tokens."""
        _, container = _make_uploader()
        container.upload_blob = AsyncMock(side_effect=Exception("sig=abc123&se=2024-01-01"))
        uploader = StorageUploader(blob_service_client=MagicMock(
            get_container_client=MagicMock(return_value=container)
        ))

        with pytest.raises(StorageUploadError) as exc_info:
            await uploader.upload_report(
                tenant_id=uuid.uuid4(),
                assessment_id=uuid.uuid4(),
                content=b"data",
                extension="pdf",
            )

        # The exception message must not contain the SAS-like token from the inner error
        assert "sig=" not in str(exc_info.value)


@pytest.mark.unit
class TestStorageUploaderContainerName:
    async def test_uses_configured_container_name(self) -> None:
        container = AsyncMock()
        container.upload_blob = AsyncMock(return_value=MagicMock())
        blob_service = MagicMock()
        blob_service.get_container_client = MagicMock(return_value=container)

        uploader = StorageUploader(
            blob_service_client=blob_service,
            container_name="my-reports-container",
        )
        await uploader.upload_report(
            tenant_id=uuid.uuid4(),
            assessment_id=uuid.uuid4(),
            content=b"data",
            extension="pdf",
        )

        blob_service.get_container_client.assert_called_with("my-reports-container")

    async def test_default_container_name(self) -> None:
        container = AsyncMock()
        container.upload_blob = AsyncMock(return_value=MagicMock())
        blob_service = MagicMock()
        blob_service.get_container_client = MagicMock(return_value=container)

        uploader = StorageUploader(blob_service_client=blob_service)
        await uploader.upload_report(
            tenant_id=uuid.uuid4(),
            assessment_id=uuid.uuid4(),
            content=b"data",
            extension="pdf",
        )

        call_name = blob_service.get_container_client.call_args[0][0]
        assert isinstance(call_name, str)
        assert len(call_name) > 0
