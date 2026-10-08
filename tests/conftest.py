"""Pytest fixtures for isolated backend and database testing."""

import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from fastapi.testclient import TestClient
from backend import app
from backend.database import Database, db as global_db
from backend.services.event_service import event_service
from backend.services.dashboard_service import dashboard_service
from backend.logging.audit_logger import audit_logger
from backend.integration.event_adapter import event_adapter


@pytest.fixture
def test_db(tmp_path):
    """Fixture providing a clean temporary SQLite database for each test."""
    db_file = str(tmp_path / "test_sage.db")
    isolated_db = Database(db_path=db_file)

    # Save original references
    orig_global_db = global_db
    orig_es_db = event_service.db
    orig_ds_db = dashboard_service.db
    orig_al_db = audit_logger.db
    orig_ea_es = event_adapter.event_service

    # Point to isolated test database
    event_service.db = isolated_db
    event_service.logger.db = isolated_db
    dashboard_service.db = isolated_db
    audit_logger.db = isolated_db
    event_adapter.event_service = event_service

    yield isolated_db

    # Restore originals
    event_service.db = orig_es_db
    event_service.logger.db = orig_al_db
    dashboard_service.db = orig_ds_db
    audit_logger.db = orig_al_db
    event_adapter.event_service = orig_ea_es


@pytest.fixture
def client(test_db):
    """Fixture providing a FastAPI TestClient configured with isolated database."""
    with TestClient(app) as test_client:
        yield test_client
