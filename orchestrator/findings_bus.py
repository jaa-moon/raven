"""
orchestrator/findings_bus.py
----------------------------
Thread-safe and async-safe shared event bus for real-time inter-agent communication.

Agent 1 (Web/API) and Agent 2 (Auth/Infra) publish confirmed findings here in real-time.
Agents can subscribe to event streams or query the snapshot for chain opportunities.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Callable, List, Optional
from reports.models import AgentFinding


class FindingsBus:
    """
    Shared event bus enabling concurrent agents to stream findings,
    subscribe to real-time discovery events, and query attack opportunities.
    """

    def __init__(self) -> None:
        self._findings: List[AgentFinding] = []
        self._lock = threading.Lock()
        self._async_queue: asyncio.Queue[AgentFinding] = asyncio.Queue()
        self._subscribers: List[Callable[[AgentFinding], None]] = []

    def publish(self, finding: AgentFinding) -> None:
        """
        Publish a newly confirmed finding to the shared bus.
        Notifies all registered synchronous subscribers and pushes to the async queue.
        """
        with self._lock:
            self._findings.append(finding)

        # Notify sync subscribers (e.g., UI dashboard updates)
        for callback in self._subscribers:
            try:
                callback(finding)
            except Exception:
                pass

        # Push to async queue for coroutine listeners
        try:
            loop = asyncio.get_running_loop()
            loop.call_soon_threadsafe(self._async_queue.put_nowait, finding)
        except RuntimeError:
            pass

    def subscribe(self, callback: Callable[[AgentFinding], None]) -> None:
        """Register a callback function to receive findings as they are published."""
        with self._lock:
            if callback not in self._subscribers:
                self._subscribers.append(callback)

    def all_findings(self) -> List[AgentFinding]:
        """Return a thread-safe snapshot of all published findings."""
        with self._lock:
            return list(self._findings)

    def findings_by_agent(self, agent: str) -> List[AgentFinding]:
        """Filter published findings by originating agent ('web_api' or 'auth_infra')."""
        with self._lock:
            return [f for f in self._findings if f.agent == agent]

    def chain_opportunities(self) -> List[AgentFinding]:
        """Return all findings that flagged a potential cross-agent attack opportunity."""
        with self._lock:
            return [f for f in self._findings if f.chain_opportunity is not None and len(f.chain_opportunity.strip()) > 0]

    async def get_next_finding(self, timeout: Optional[float] = None) -> Optional[AgentFinding]:
        """Async queue reader for coroutines listening for new findings with an optional timeout."""
        try:
            if timeout is not None:
                return await asyncio.wait_for(self._async_queue.get(), timeout=timeout)
            return await self._async_queue.get()
        except asyncio.TimeoutError:
            return None
