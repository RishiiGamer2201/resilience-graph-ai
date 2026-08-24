"""A token bucket, per principal, for the endpoints that cost something.

There was no rate limiting anywhere in the service. Two endpoints made that
matter:

  * POST /api/analyze runs a multi-second CPU pipeline -- read, score,
    correlate, graph, SOAR, attribute, report;
  * POST /api/agents/reason makes up to fourteen provider calls per request and
    spends third-party quota. It already retries on 429, so one caller could
    burn the whole minute's budget for everyone else.

Both are reachable by anyone with a role header, and in demo-headers mode the
role is self-declared.

Deliberately stdlib: a dict and `time.monotonic()`. ADR 0001 keeps this to one
container, and a limiter is not a good reason to add Redis to a project whose
whole deployment story is that it does not need one. The cost of that choice is
stated rather than hidden: the buckets are per PROCESS, so N workers allow N
times the rate. That is the right trade at this scale and the wrong one at the
scale where you would want a shared store, which is the point at which this
module should be replaced rather than tuned.

`monotonic`, not `time()`: a wall-clock step backwards would hand out free
tokens, and NTP does that routinely.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


@dataclass
class Bucket:
    """`capacity` tokens, refilled at `capacity / per_seconds`, never above full."""

    capacity: float
    per_seconds: float
    tokens: float = field(init=False)
    updated: float = field(init=False)

    def __post_init__(self) -> None:
        self.tokens = float(self.capacity)
        self.updated = time.monotonic()

    def take(self, n: float = 1.0) -> tuple[bool, float]:
        """Spend `n` tokens. Returns (allowed, seconds until the next one)."""
        now = time.monotonic()
        rate = self.capacity / self.per_seconds
        self.tokens = min(self.capacity, self.tokens + (now - self.updated) * rate)
        self.updated = now
        if self.tokens >= n:
            self.tokens -= n
            return True, 0.0
        return False, max(0.0, (n - self.tokens) / rate)


class Limiter:
    """Named buckets keyed on (bucket name, principal)."""

    # Bucket name -> (requests, per seconds). Generous on purpose: this exists
    # to stop one caller monopolising the box, not to meter a product.
    LIMITS: dict[str, tuple[float, float]] = {
        "analyze": (12, 60.0),   # a multi-second CPU pipeline
        "agents": (6, 60.0),     # up to 14 provider calls each, shared quota
    }

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buckets: dict[tuple[str, str], Bucket] = {}

    def check(self, name: str, who: str) -> tuple[bool, float]:
        limit = self.LIMITS.get(name)
        if not limit:
            return True, 0.0
        cap, per = limit
        with self._lock:
            key = (name, who)
            b = self._buckets.get(key)
            if b is None:
                b = self._buckets[key] = Bucket(cap, per)
            # Unbounded key growth is the classic bug in this pattern: one key
            # per actor, and actors are self-declared. Full buckets are at rest
            # and carry no state worth keeping, so they are safe to drop.
            if len(self._buckets) > 4096:
                self._buckets = {
                    k: v for k, v in self._buckets.items()
                    if k == key or v.tokens < v.capacity
                }
            return b.take()

    def reset(self) -> None:
        """For tests. Not reachable from any endpoint."""
        with self._lock:
            self._buckets.clear()


_limiter = Limiter()


def check(name: str, who: str) -> tuple[bool, float]:
    return _limiter.check(name, who)


def reset() -> None:
    _limiter.reset()


def demo() -> None:
    """Self-check: a bucket empties, refuses, refills, and never overfills."""
    b = Bucket(capacity=3, per_seconds=60.0)
    assert all(b.take()[0] for _ in range(3)), "a full bucket must spend its tokens"
    allowed, wait = b.take()
    assert not allowed and wait > 0, "an empty bucket must refuse and say for how long"

    # Refill is proportional to elapsed time, not to calls.
    b.updated -= 30.0                      # half the window
    assert b.take()[0], "half a window must buy back at least one token"

    b.updated -= 10_000.0
    b.take()
    assert b.tokens <= b.capacity, "refill must never exceed capacity"

    l = Limiter()
    who = "asha@soc"
    ok = sum(l.check("agents", who)[0] for _ in range(20))
    assert ok == Limiter.LIMITS["agents"][0], f"expected the cap, got {ok}"
    assert l.check("agents", "someone.else@soc")[0], "buckets are per principal"
    assert l.check("no_such_bucket", who)[0], "an unnamed bucket is not a limit"
    print(f"ratelimit ok: {len(Limiter.LIMITS)} buckets, refill is time-based, "
          f"per-principal, and an unknown name never blocks")


if __name__ == "__main__":
    demo()
