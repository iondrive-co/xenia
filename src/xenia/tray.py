from __future__ import annotations

import sys
from typing import Callable


class Unavailable(RuntimeError):
    pass


class MenuItem:
    def __init__(self, label: str, action: Callable[[], None]) -> None:
        self.label = label
        self.action = action


class Tray:
    def __init__(self, title: str, items: list[MenuItem]) -> None:
        self.title = title
        self.items = items
        self._backend = None
        self._timers: list[tuple[int, Callable[[], bool]]] = []

    def click(self, item_id: int) -> None:
        if 1 <= item_id <= len(self.items):
            self.items[item_id - 1].action()

    def fire_default(self) -> None:
        if self.items:
            self.items[0].action()

    def every(self, seconds: int, callback: Callable[[], bool]) -> None:
        self._timers.append((seconds, callback))

    def start(self) -> None:
        self._backend = _backend(self)
        for seconds, callback in self._timers:
            self._backend.every(seconds, callback)
        try:
            self._backend.start()
        except Exception as exc:
            self._backend = None
            if isinstance(exc, Unavailable):
                raise
            raise Unavailable(str(exc)) from exc

    def stop(self) -> None:
        if self._backend is not None:
            self._backend.stop()


def _backend(owner: Tray):
    if sys.platform == "darwin":
        from . import tray_macos
        return tray_macos.Backend(owner)
    if sys.platform.startswith("linux"):
        from . import tray_linux
        return tray_linux.Backend(owner)
    raise Unavailable(
        f"no tray backend for {sys.platform} — the report and the recording "
        f"still work")


def available() -> bool:
    try:
        if sys.platform == "darwin":
            from . import tray_macos
            return tray_macos.available()
        if sys.platform.startswith("linux"):
            from . import tray_linux
            return tray_linux.available()
    except Exception:
        return False
    return False
