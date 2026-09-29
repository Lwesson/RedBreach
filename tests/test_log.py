"""Tests for logging setup (previously untested; had a duplicate-handler bug)."""
import logging

from redbreach.log import setup_logging


def test_setup_logging_creates_handlers_and_file(tmp_path):
    logger = setup_logging(tmp_path)
    kinds = {type(h).__name__ for h in logger.handlers}
    assert "RotatingFileHandler" in kinds
    assert "StreamHandler" in kinds
    assert (tmp_path / "redbreach.log").exists()


def test_setup_logging_is_idempotent(tmp_path):
    # The CLI group AND each subcommand both call setup_logging; repeated calls
    # must NOT stack duplicate handlers (that double-logged every line).
    first = setup_logging(tmp_path)
    count = len(first.handlers)
    second = setup_logging(tmp_path)
    assert second is first                 # same named logger
    assert len(second.handlers) == count   # no duplicates
    assert count == 2                       # exactly file + console


def test_setup_logging_respects_level(tmp_path):
    logger = setup_logging(tmp_path, level="DEBUG")
    assert logger.level == logging.DEBUG
