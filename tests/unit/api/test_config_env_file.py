"""Regression tests: .env file loading behaviour for Settings.

Proves that DB_PASSWORD (and other fields) in a .env file override the
hardcoded defaults when Settings is instantiated outside the test runner,
while also verifying that environment variables take priority over .env.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from waf_api.config import Settings


@pytest.mark.unit
class TestEnvFileLoading:
    def test_db_password_from_env_file_overrides_default(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """DB_PASSWORD in .env must override the hardcoded 'changeme' default."""
        monkeypatch.delenv("DB_PASSWORD", raising=False)
        env_file = tmp_path / ".env"
        env_file.write_text("DB_PASSWORD=from_dotenv\n", encoding="utf-8")

        s = Settings(_env_file=str(env_file))

        assert s.db_password.get_secret_value() == "from_dotenv"

    def test_env_var_takes_precedence_over_env_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A real environment variable must win over a .env file value."""
        monkeypatch.setenv("DB_PASSWORD", "from_env_var")
        env_file = tmp_path / ".env"
        env_file.write_text("DB_PASSWORD=from_dotenv\n", encoding="utf-8")

        s = Settings(_env_file=str(env_file))

        assert s.db_password.get_secret_value() == "from_env_var"

    def test_multiple_fields_loaded_from_env_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """All fields present in .env are applied to Settings."""
        for var in ("DB_PASSWORD", "DB_HOST", "DB_USER"):
            monkeypatch.delenv(var, raising=False)
        env_file = tmp_path / ".env"
        env_file.write_text(
            "DB_PASSWORD=secret123\nDB_HOST=pg.internal\nDB_USER=svc_acct\n",
            encoding="utf-8",
        )

        s = Settings(_env_file=str(env_file))

        assert s.db_password.get_secret_value() == "secret123"
        assert s.db_host == "pg.internal"
        assert s.db_user == "svc_acct"
