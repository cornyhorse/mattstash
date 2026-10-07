"""Throttling of failed authentication attempts, per client address.

This runs *before* authentication in the middleware: once a client has accumulated too many
failures within the window every request from it is answered ``429`` without touching the key
store, so keys cannot be brute-forced at line speed. Only failures count (a valid key never
resets the counter), so legitimate clients are unaffected.
"""

import math
import threading
import time
from collections import deque
from typing import Callable


class FailureTracker:
    """Sliding-window counter of failed attempts, bounded in memory."""

    def __init__(
        self,
        limit: Callable[[], int],
        window_seconds: Callable[[], int],
        *,
        max_clients: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._limit = limit
        self._window = window_seconds
        self._max_clients = max_clients
        self._clock = clock
        self._failures: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, client: str, now: float) -> deque[float]:
        attempts = self._failures.get(client)
        if attempts is None:
            return deque()
        horizon = now - self._window()
        while attempts and attempts[0] <= horizon:
            attempts.popleft()
        if not attempts:
            del self._failures[client]
            return deque()
        return attempts

    def record_failure(self, client: str) -> None:
        with self._lock:
            now = self._clock()
            attempts = self._prune(client, now)
            attempts.append(now)
            self._failures[client] = attempts
            if len(self._failures) > self._max_clients:
                self._evict(now)

    def retry_after(self, client: str) -> int:
        """Seconds until ``client`` may try again; 0 if it is not blocked."""
        with self._lock:
            now = self._clock()
            attempts = self._prune(client, now)
            if len(attempts) < self._limit():
                return 0
            # blocked until enough old failures age out to drop below the limit
            release_at = attempts[len(attempts) - self._limit()] + self._window()
            return max(1, math.ceil(release_at - now))

    def reset(self) -> None:
        with self._lock:
            self._failures.clear()

    def _evict(self, now: float) -> None:
        for client in list(self._failures):
            self._prune(client, now)
        while len(self._failures) > self._max_clients:  # still too many: drop the oldest-inserted
            self._failures.pop(next(iter(self._failures)))
