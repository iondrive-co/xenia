from __future__ import annotations

import sys
from typing import Callable


class Unavailable(RuntimeError):
    pass


class MenuItem:
    """One entry. With `items` it is a submenu and its own action is unused."""

    def __init__(self, label: str, action: Callable[[], None] | None = None,
                 items: "list[MenuItem] | None" = None) -> None:
        self.label = label
        self.action = action or (lambda: None)
        self.items = items or []


class Tray:
    def __init__(self, title: str, items: list[MenuItem]) -> None:
        self.title = title
        self.items = items
        self._backend = None
        self._timers: list[tuple[int, Callable[[], bool]]] = []

    def numbered(self) -> list[tuple[int, "MenuItem", int]]:
        """Every entry as (id, item, parent id), depth first.

        One flat numbering across the whole tree, because a click arrives as
        an id and nothing else.
        """
        out: list[tuple[int, MenuItem, int]] = []

        def walk(items: list[MenuItem], parent: int) -> None:
            for item in items:
                identifier = len(out) + 1
                out.append((identifier, item, parent))
                walk(item.items, identifier)

        walk(self.items, 0)
        return out

    def flattened(self) -> list[MenuItem]:
        """The tree as one list, for a backend that cannot nest."""
        out: list[MenuItem] = []
        for item in self.items:
            if not item.items:
                out.append(item)
                continue
            out.extend(MenuItem(f"{item.label}: {child.label}", child.action)
                       for child in item.items)
        return out

    def find(self, item_id: int) -> "MenuItem | None":
        for identifier, item, _parent in self.numbered():
            if identifier == item_id:
                return item
        return None

    def click(self, item_id: int) -> None:
        item = self.find(item_id)
        if item is not None and not item.items:
            item.action()

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
