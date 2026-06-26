"""Cross-platform asyncio signal handling for agent entry points.

asyncio.ProactorEventLoop (default on Windows since Python 3.8) raises
NotImplementedError for add_signal_handler.  This module provides a single
install_signal_handlers() call that works on Windows, Linux, and macOS.
"""

from __future__ import annotations

import asyncio
import signal
import sys


def install_signal_handlers(stop_event: asyncio.Event) -> None:
    """Register SIGTERM/SIGINT to set stop_event, cross-platform.

    Must be called from inside a running coroutine (i.e. from within asyncio.run()).

    Unix/macOS — loop.add_signal_handler():
        Callbacks run directly on the event loop thread; no locking needed.

    Windows — signal.signal() + call_soon_threadsafe():
        ProactorEventLoop does not implement add_signal_handler.  C-runtime
        signal handlers fire on the main OS thread; call_soon_threadsafe
        safely schedules stop_event.set() on the running event loop.
        Installing a handler for SIGINT replaces Python's default
        KeyboardInterrupt behaviour with a graceful stop, matching Unix.
    """
    loop = asyncio.get_running_loop()
    if sys.platform == "win32":
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda _s, _f: loop.call_soon_threadsafe(stop_event.set))
    else:
        loop.add_signal_handler(signal.SIGTERM, stop_event.set)
        loop.add_signal_handler(signal.SIGINT, stop_event.set)
