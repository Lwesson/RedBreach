import pytest
from unittest.mock import AsyncMock

from redbreach.ops.monitor import Monitor, MonitorConfig

_ENG = {"id": 1, "target": "example.com", "type": "bounty"}


def _pipeline(before=None, after=None, engagement=_ENG, run_error=None):
    pipeline = AsyncMock()
    pipeline.run = AsyncMock(side_effect=run_error)
    db = AsyncMock()
    db.get_engagement = AsyncMock(return_value=engagement)
    db.get_findings = AsyncMock(side_effect=[before or [], after or []])
    pipeline.db = db
    return pipeline


def test_config_defaults():
    cfg = MonitorConfig()
    assert cfg.interval_seconds == 3600
    assert cfg.phases == [2, 4]


def test_config_custom():
    cfg = MonitorConfig(interval_seconds=1800, phases=[2, 3, 4, 5])
    assert cfg.interval_seconds == 1800
    assert len(cfg.phases) == 4


@pytest.mark.asyncio
async def test_monitor_runs_pipeline_with_engagement_dict():
    # Regression: it must pass the engagement DICT, not the int id, to pipeline.run.
    pipeline = _pipeline()
    monitor = Monitor(config=MonitorConfig(phases=[2, 4]), pipeline=pipeline, engagement_id=1)
    await monitor.run_cycle()
    pipeline.run.assert_called_once_with(_ENG, phases=[2, 4])


@pytest.mark.asyncio
async def test_monitor_detects_new_findings():
    pipeline = _pipeline(before=[{"id": 1}], after=[{"id": 1}, {"id": 2}])
    monitor = Monitor(config=MonitorConfig(), pipeline=pipeline, engagement_id=1)
    new = await monitor.run_cycle()
    assert [f["id"] for f in new] == [2]


@pytest.mark.asyncio
async def test_monitor_no_new_findings_returns_empty():
    pipeline = _pipeline(before=[{"id": 1}], after=[{"id": 1}])
    monitor = Monitor(config=MonitorConfig(), pipeline=pipeline, engagement_id=1)
    assert await monitor.run_cycle() == []


@pytest.mark.asyncio
async def test_monitor_missing_engagement_skips():
    pipeline = _pipeline(engagement=None)
    monitor = Monitor(config=MonitorConfig(), pipeline=pipeline, engagement_id=99)
    assert await monitor.run_cycle() == []
    pipeline.run.assert_not_called()


@pytest.mark.asyncio
async def test_monitor_handles_pipeline_error():
    pipeline = _pipeline(before=[], run_error=RuntimeError("scan failed"))
    monitor = Monitor(config=MonitorConfig(), pipeline=pipeline, engagement_id=1)
    assert await monitor.run_cycle() == []  # swallowed, no raise
