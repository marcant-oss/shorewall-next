"""Shared base for ingress-path metric classes (pbdns + dnstap)."""

from __future__ import annotations

import time


class _IngressMetricsBase:
    """Lock-free counter bag for ingress-path metrics.

    Subclasses declare their counter names via a class-level
    ``_COUNTER_NAMES`` tuple.  ``__init__`` initialises each counter to 0.
    ``inc`` assumes the key already exists and raises ``KeyError`` on
    an unknown name — fail fast during development.

    Under the GIL, ``self._counters[name] += n`` is atomic for int
    counters whose key is pre-registered:  the dict lookup resolves to a
    single ``BINARY_SUBSCR`` + ``INPLACE_ADD`` + ``STORE_SUBSCR`` sequence,
    all of which hold the GIL for their entire duration.  No lock is needed
    on the 40 k/s hot path.

    Adding a new counter requires an entry in the subclass's
    ``_COUNTER_NAMES`` tuple; forgetting raises ``KeyError`` in tests.
    """

    # Subclasses override this at class level.
    _COUNTER_NAMES: tuple[str, ...] = ()

    def __init__(self) -> None:
        self._counters: dict[str, int] = {
            name: 0 for name in self._COUNTER_NAMES
        }
        self.last_frame_mono: float = 0.0

    def __getattr__(self, name: str) -> int:
        """Attribute-style read for pre-registered counters.

        Allows ``metrics.frames_accepted`` as an alias for
        ``metrics._counters["frames_accepted"]``.  Only invoked when
        normal attribute lookup fails — never for ``_counters`` itself
        (which is set in ``__init__``) or any real instance attribute.

        Raises ``AttributeError`` for any name not in ``_counters``.
        """
        # Guard against infinite recursion during pickling / deepcopy
        # which probe attributes before __init__ runs.
        counters = self.__dict__.get("_counters")
        if counters is not None and name in counters:
            return counters[name]
        raise AttributeError(
            f"{type(self).__name__!r} object has no attribute {name!r}")

    def inc(self, name: str, n: int = 1) -> None:
        """Increment *name* by *n*.

        Atomic under the GIL; no lock needed for simple integer counters
        that are pre-registered in ``_COUNTER_NAMES``.

        Raises ``KeyError`` if *name* was not registered — fail fast so
        developers catch missing registrations in tests rather than
        silently losing increments.
        """
        try:
            self._counters[name] += n
        except KeyError:
            raise KeyError(
                f"{type(self).__name__}: unregistered counter {name!r}. "
                f"Add it to the class-level _COUNTER_NAMES tuple."
            ) from None

    def snapshot(self) -> dict[str, int]:
        """Return a shallow copy of the counter dict.

        Thread-safe under the GIL: ``dict.copy()`` is a single C call
        and holds the GIL for its entire duration, so no concurrent
        ``inc()`` can interleave.
        """
        return self._counters.copy()

    def set_last_frame_now(self) -> None:
        """Record the current monotonic timestamp as the last frame time."""
        self.last_frame_mono = time.monotonic()
