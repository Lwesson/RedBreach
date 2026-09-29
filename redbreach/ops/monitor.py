"""Continuous monitoring daemon."""
import asyncio
import logging
from dataclasses import dataclass, field

logger = logging.getLogger("redbreach.ops.monitor")

@dataclass
class MonitorConfig:
    interval_seconds: int = 3600
    phases: list[int] = field(default_factory=lambda: [2, 4])
    max_cycles: int | None = None

class Monitor:
    def __init__(self, config: MonitorConfig, pipeline, engagement_id: int) -> None:
        self.config = config
        self.pipeline = pipeline
        self.engagement_id = engagement_id
        self._running = False
        self._cycle_count = 0

    async def run_cycle(self) -> list[dict]:
        """Run one monitoring pass and return findings that are new since last cycle."""
        self._cycle_count += 1
        logger.info("Monitor cycle %d for engagement %d", self._cycle_count, self.engagement_id)
        db = self.pipeline.db

        # Pipeline.run needs the engagement dict, not the id.
        engagement = await db.get_engagement(self.engagement_id)
        if not engagement:
            logger.error("Monitor: engagement %d not found; skipping cycle", self.engagement_id)
            return []

        before_ids = {f.get("id") for f in await db.get_findings(self.engagement_id)}
        try:
            await self.pipeline.run(engagement, phases=self.config.phases)
        except Exception as e:
            logger.error("Monitor cycle failed: %s", e)
            return []

        new_findings = [f for f in await db.get_findings(self.engagement_id)
                        if f.get("id") not in before_ids]
        if new_findings:
            logger.warning("Monitor: %d new finding(s) since last cycle for engagement %d",
                           len(new_findings), self.engagement_id)
        return new_findings

    async def start(self) -> None:
        self._running = True
        logger.info("Monitor started (interval=%ds, phases=%s)", self.config.interval_seconds, self.config.phases)
        while self._running:
            await self.run_cycle()
            if self.config.max_cycles and self._cycle_count >= self.config.max_cycles:
                break
            await asyncio.sleep(self.config.interval_seconds)

    def stop(self) -> None:
        self._running = False
        logger.info("Monitor stopped after %d cycles", self._cycle_count)
