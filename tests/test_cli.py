import pytest
from click.testing import CliRunner
from unittest.mock import patch, AsyncMock, MagicMock

from redbreach.cli import main


@pytest.fixture
def runner():
    return CliRunner()


def test_cli_version(runner):
    """--version prints version."""
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_cli_health(runner):
    """health command runs without error."""
    with patch("redbreach.cli.asyncio") as mock_asyncio:
        mock_asyncio.run = MagicMock()
        result = runner.invoke(main, ["health"])
        assert result.exit_code == 0


def test_cli_list_empty(runner):
    """list command works with no engagements."""
    with patch("redbreach.cli.asyncio") as mock_asyncio:
        mock_asyncio.run = MagicMock(return_value=[])
        result = runner.invoke(main, ["list"])
        assert result.exit_code == 0


def test_cli_help(runner):
    """--help shows available commands."""
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "new" in result.output
    assert "scan" in result.output
    assert "health" in result.output
    assert "list" in result.output
    assert "findings" in result.output
    assert "report" in result.output


def test_cli_help_shows_resume(runner):
    result = runner.invoke(main, ["--help"])
    assert "resume" in result.output


def test_cli_help_shows_session(runner):
    result = runner.invoke(main, ["--help"])
    assert "session" in result.output


def test_cli_help_shows_coverage_and_mobile(runner):
    result = runner.invoke(main, ["--help"])
    assert "coverage" in result.output
    assert "mobile" in result.output
