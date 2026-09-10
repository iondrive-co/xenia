from __future__ import annotations

import os
import threading
import time
from typing import Callable

from . import dbus, icon
from .tray import Unavailable

ITEM_PATH = "/StatusNotifierItem"
MENU_PATH = "/MenuBar"
ITEM_IFACE = "org.kde.StatusNotifierItem"
MENU_IFACE = "com.canonical.dbusmenu"
PROPS_IFACE = "org.freedesktop.DBus.Properties"
INTROSPECT_IFACE = "org.freedesktop.DBus.Introspectable"
WATCHER = "org.kde.StatusNotifierWatcher"

MENU_REVISION = 1


class Backend:
    def __init__(self, owner) -> None:
        self.owner = owner
        self.conn: dbus.Connection | None = None
        self._stop = threading.Event()
        self._timers: list[tuple[int, Callable[[], bool], list[float]]] = []


    def start(self) -> None:
        try:
            self.conn = dbus.Connection().connect()
        except Exception as exc:
            raise Unavailable(f"no session bus: {exc}") from exc

        if not self.conn.name_has_owner(WATCHER):
            self.conn.close()
            raise Unavailable(
                "no org.kde.StatusNotifierWatcher on the session bus — this "
                "desktop is not running a tray host")

        self.conn.export(ITEM_PATH, ITEM_IFACE, self._item_method)
        self.conn.export(ITEM_PATH, PROPS_IFACE, self._item_props)
        self.conn.export(ITEM_PATH, INTROSPECT_IFACE, self._introspect)
        self.conn.export(MENU_PATH, MENU_IFACE, self._menu_method)
        self.conn.export(MENU_PATH, PROPS_IFACE, self._menu_props)
        self.conn.export(MENU_PATH, INTROSPECT_IFACE, self._introspect)

        name = f"org.kde.StatusNotifierItem-{os.getpid()}-1"
        self.conn.request_name(name)
        try:
            self.conn.call(WATCHER, "/StatusNotifierWatcher", WATCHER,
                           "RegisterStatusNotifierItem", "s", [name])
        except dbus.DBusError as exc:
            self.conn.close()
            raise Unavailable(f"the tray host refused registration: {exc}") from exc

        self._run_loop()

    def _run_loop(self) -> None:
        while not self._stop.is_set():
            now = time.monotonic()
            for seconds, callback, due in list(self._timers):
                if now >= due[0]:
                    due[0] = now + seconds
                    try:
                        if callback() is False:
                            self._timers = [t for t in self._timers if t[1] is not callback]
                    except Exception:
                        pass
            self._stop.wait(0.5)

        if self.conn is not None:
            self.conn.close()

    def stop(self) -> None:
        self._stop.set()

    def every(self, seconds: int, callback: Callable[[], bool]) -> None:
        self._timers.append((seconds, callback, [time.monotonic() + seconds]))


    def _item_property(self, name: str) -> dbus.Variant | None:
        owner = self.owner
        if name == "Category":
            return dbus.Variant("s", "ApplicationStatus")
        if name in ("Id", "Title"):
            return dbus.Variant("s", owner.title)
        if name == "Status":
            return dbus.Variant("s", "Active")
        if name in ("IconName", "OverlayIconName", "AttentionIconName"):
            return dbus.Variant("s", "")
        if name == "IconPixmap":
            width, height, argb = icon.argb_for_dbus()
            return dbus.Variant("a(iiay)", [(width, height, argb)])
        if name == "ToolTip":
            return dbus.Variant("(sa(iiay)ss)", ("", [], owner.title, ""))
        if name == "ItemIsMenu":
            return dbus.Variant("b", False)
        if name == "Menu":
            return dbus.Variant("o", MENU_PATH)
        return None

    _ITEM_PROPS = ("Category", "Id", "Title", "Status", "IconName", "IconPixmap",
                   "OverlayIconName", "AttentionIconName", "ToolTip",
                   "ItemIsMenu", "Menu")

    def _menu_property(self, name: str) -> dbus.Variant | None:
        return {
            "Version": dbus.Variant("u", 3),
            "TextDirection": dbus.Variant("s", "ltr"),
            "Status": dbus.Variant("s", "normal"),
            "IconThemePath": dbus.Variant("as", []),
        }.get(name)

    _MENU_PROPS = ("Version", "TextDirection", "Status", "IconThemePath")

    def _props_handler(self, message, lookup, names):
        if message.member == "Get":
            _iface, prop = message.body
            value = lookup(prop)
            if value is None:
                raise dbus.DBusError(f"no such property: {prop}")
            return "v", [value]
        if message.member == "GetAll":
            found = {name: lookup(name) for name in names}
            return "a{sv}", [{k: v for k, v in found.items() if v is not None}]
        if message.member == "Set":
            raise dbus.DBusError("all properties are read-only")
        raise dbus.DBusError(f"unknown method: {message.member}")

    def _item_props(self, message):
        return self._props_handler(message, self._item_property, self._ITEM_PROPS)

    def _menu_props(self, message):
        return self._props_handler(message, self._menu_property, self._MENU_PROPS)

    def _introspect(self, message):
        return "s", ["<node/>"]


    def _item_method(self, message):
        if message.member in ("Activate", "SecondaryActivate"):
            self.owner.fire_default()
        return "", []

    def _item_properties_for(self, item):
        props = {
            "label": dbus.Variant("s", item.label),
            "enabled": dbus.Variant("b", True),
            "visible": dbus.Variant("b", True),
        }
        if item.items:
            props["children-display"] = dbus.Variant("s", "submenu")
        return props

    def _branch(self, identifier, item):
        return dbus.Variant("(ia{sv}av)", (
            identifier, self._item_properties_for(item),
            [self._branch(child_id, child)
             for child_id, child, parent in self.owner.numbered()
             if parent == identifier]))

    def _layout(self):
        children = [self._branch(identifier, item)
                    for identifier, item, parent in self.owner.numbered()
                    if parent == 0]
        return (0, {"children-display": dbus.Variant("s", "submenu")}, children)

    def _menu_method(self, message):
        member = message.member

        if member == "GetLayout":
            return "u(ia{sv}av)", [MENU_REVISION, self._layout()]

        if member == "GetGroupProperties":
            return "a(ia{sv})", [[
                (identifier, self._item_properties_for(item))
                for identifier, item, _parent in self.owner.numbered()
            ]]

        if member == "GetProperty":
            item_id, name = message.body
            item = self.owner.find(item_id)
            props = self._item_properties_for(item) if item else {}
            return "v", [props.get(name, dbus.Variant("s", ""))]

        if member == "Event":
            item_id, event_id = message.body[0], message.body[1]
            if event_id == "clicked":
                self.owner.click(item_id)
            return "", []

        if member == "EventGroup":
            for entry in message.body[0]:
                if entry[1] == "clicked":
                    self.owner.click(entry[0])
            return "ai", [[]]

        if member == "AboutToShow":
            return "b", [False]

        if member == "AboutToShowGroup":
            return "aiai", [[], []]

        raise dbus.DBusError(f"unknown method: {member}")


def available() -> bool:
    try:
        dbus.session_bus_address()
        return True
    except dbus.DBusError:
        return False
