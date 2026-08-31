"""Telemetry collector daemon.

Reads events from a honeypot adapter, stores them, sessionizes, and triggers
the analysis pipeline for new sessions. Runs in a background thread.
"""

import threading
import time
from typing import List, Optional

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.honeypot.base import HoneypotAdapter
from app.services.analysis_service import AnalysisService
from app.telemetry.pipeline import TelemetryPipeline, normalize
from app.websocket.bus import publish_telemetry

settings = get_settings()
logger = get_logger("collector")


class TelemetryCollector:
    def __init__(self, db_factory, adapter: HoneypotAdapter):
        self.db_factory = db_factory
        self.adapter = adapter
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.session_ids_analysed: set = set()
        self.stats = {"collected": 0, "analysed": 0}

    def _run_cycle(self) -> None:
        db: Session = self.db_factory()
        try:
            pipeline = TelemetryPipeline(db)
            raw = list(self.adapter.read_events())
            if raw:
                ingested = pipeline.ingest_raw(raw)
                session_ids = pipeline.create_or_update_session(raw)
                pipeline.recount_events()
                self.stats["collected"] += ingested["stored"]

                # Publish raw events to live dashboard subscribers
                for ev in raw:
                    try:
                        ne = normalize(ev)
                        publish_telemetry(
                            "event",
                            {
                                "event_id": ne.event_id,
                                "timestamp": ne.timestamp.isoformat(),
                                "session": ne.session_id,
                                "service": ne.service,
                                "event_type": ne.event_type,
                                "action": ne.action,
                                "target": ne.target,
                                "result": ne.result,
                                "source": ne.source,
                            },
                        )
                    except Exception:
                        continue

                # Analyse newly closed sessions
                analysis_service = AnalysisService(db, adapter=self.adapter)
                for sid in session_ids:
                    if sid and sid not in self.session_ids_analysed:
                        try:
                            analysis_service.analyse(sid, apply_deception=True)
                            self.session_ids_analysed.add(sid)
                            self.stats["analysed"] += 1
                        except Exception as e:
                            logger.error("Analysis failed for session %s: %s", sid, e)
        finally:
            db.close()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        logger.info("Collector started for adapter %s", self.adapter.name)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._run_cycle()
            except Exception as e:
                logger.error("Collector cycle error: %s", e)
            self._stop.wait(settings.HONEYPOT_POLL_INTERVAL)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def status(self) -> dict:
        return {
            "adapter": self.adapter.name,
            "running": self._thread is not None and self._thread.is_alive(),
            **self.stats,
        }
