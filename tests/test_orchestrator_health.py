"""Tests for orchestrator liveness heuristics (Phase A subtask 1, Web side).

Phase A makes guardian_heartbeat_at (written by mirror_ops on every status
write) the authoritative liveness signal, superseding the finished_at heuristic
which is kept only as a back-compat fallback for older Mirror builds.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from app.main import _orchestrator_alive


def _iso(seconds_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat(
        timespec="seconds"
    )


class OrchestratorHealthTests(unittest.TestCase):
    def test_running_state_is_alive(self) -> None:
        self.assertTrue(_orchestrator_alive({"state": "running"}))

    def test_fresh_heartbeat_is_alive(self) -> None:
        self.assertTrue(
            _orchestrator_alive({"state": "idle", "guardian_heartbeat_at": _iso(5)})
        )

    def test_stale_heartbeat_is_dead(self) -> None:
        # default TTL is 900s; 100000s ago is well past it
        self.assertFalse(
            _orchestrator_alive(
                {"state": "idle", "guardian_heartbeat_at": _iso(100000)}
            )
        )

    def test_heartbeat_overrides_finished_when_both_present(self) -> None:
        # heartbeat is authoritative: fresh heartbeat + old finished → alive
        self.assertTrue(
            _orchestrator_alive(
                {
                    "state": "completed",
                    "guardian_heartbeat_at": _iso(5),
                    "finished_at": _iso(100000),
                }
            )
        )

    def test_stale_heartbeat_overrides_recent_finished(self) -> None:
        # stale heartbeat + recent finished → dead (heartbeat authoritative)
        self.assertFalse(
            _orchestrator_alive(
                {
                    "state": "completed",
                    "guardian_heartbeat_at": _iso(100000),
                    "finished_at": _iso(5),
                }
            )
        )

    def test_no_heartbeat_falls_back_to_finished_recent(self) -> None:
        # back-compat: older Mirror without heartbeat uses finished_at heuristic
        self.assertTrue(
            _orchestrator_alive({"state": "completed", "finished_at": _iso(100)})
        )

    def test_no_heartbeat_no_finished_is_dead(self) -> None:
        self.assertFalse(_orchestrator_alive({"state": "idle"}))


if __name__ == "__main__":
    unittest.main()
