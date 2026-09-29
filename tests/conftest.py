import asyncio
import tempfile
from pathlib import Path

import pytest
import pytest_asyncio

from redbreach.db import Database


@pytest.fixture
def tmp_dir(tmp_path):
    """Temporary directory for test data."""
    return tmp_path


@pytest_asyncio.fixture
async def db(tmp_path):
    """Fresh test database."""
    db_path = tmp_path / "test.db"
    database = Database(str(db_path))
    await database.initialize()
    yield database
    await database.close()


@pytest.fixture
def fixtures_dir():
    """Path to test fixtures directory."""
    return Path(__file__).parent / "fixtures"
