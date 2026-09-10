from __future__ import annotations

import ctypes
import ctypes.util
import sys
from typing import Callable

from . import icon
from .tray import Unavailable

objc_id = ctypes.c_void_p
SEL = ctypes.c_void_p
Class = ctypes.c_void_p

NSSquareStatusItemLength = -2.0
NSVariableStatusItemLength = -1.0


class _Runtime:
    def __init__(self) -> None:
        objc_path = ctypes.util.find_library("objc")
        if objc_path is None:
            raise Unavailable("libobjc not found — is this really macOS?")
        self.objc = ctypes.cdll.LoadLibrary(objc_path)

        appkit = ctypes.util.find_library("AppKit")
        if appkit is None:
            raise Unavailable("AppKit not found")
        ctypes.cdll.LoadLibrary(appkit)

        self.objc.objc_getClass.restype = Class
        self.objc.objc_getClass.argtypes = [ctypes.c_char_p]
        self.objc.sel_registerName.restype = SEL
        self.objc.sel_registerName.argtypes = [ctypes.c_char_p]
        self.objc.objc_allocateClassPair.restype = Class
        self.objc.objc_allocateClassPair.argtypes = [Class, ctypes.c_char_p, ctypes.c_size_t]
        self.objc.objc_registerClassPair.argtypes = [Class]
        self.objc.class_addMethod.restype = ctypes.c_bool
        self.objc.class_addMethod.argtypes = [Class, SEL, ctypes.c_void_p, ctypes.c_char_p]

        self._senders: dict[tuple, ctypes.CFUNCTYPE] = {}

    def cls(self, name: str) -> Class:
        handle = self.objc.objc_getClass(name.encode())
        if not handle:
            raise Unavailable(f"Objective-C class {name} is not registered")
        return handle

    def sel(self, name: str) -> SEL:
        return self.objc.sel_registerName(name.encode())

    def send(self, receiver, selector: str, *args, restype=objc_id, argtypes=()):
        key = (restype, argtypes)
        sender = self._senders.get(key)
        if sender is None:
            prototype = ctypes.CFUNCTYPE(restype, objc_id, SEL, *argtypes)
            sender = prototype(("objc_msgSend", self.objc))
            self._senders[key] = sender
        return sender(receiver, self.sel(selector), *args)


class Backend:
    def __init__(self, owner) -> None:
        self.owner = owner
        self.rt: _Runtime | None = None
        self._app = None
        self._item = None
        self._callbacks: list = []
        self._targets: list = []
        self._timers: list = []
        self._stopped = False


    def start(self) -> None:
        if sys.platform != "darwin":
            raise Unavailable("the macOS backend only runs on macOS")

        self.rt = rt = _Runtime()

        app_cls = rt.cls("NSApplication")
        self._app = rt.send(app_cls, "sharedApplication")
        NSApplicationActivationPolicyAccessory = 1
        rt.send(self._app, "setActivationPolicy:",
                ctypes.c_long(NSApplicationActivationPolicyAccessory),
                restype=ctypes.c_bool, argtypes=[ctypes.c_long])

        status_bar = rt.send(rt.cls("NSStatusBar"), "systemStatusBar")
        self._item = rt.send(status_bar, "statusItemWithLength:",
                             ctypes.c_double(NSSquareStatusItemLength),
                             argtypes=[ctypes.c_double])
        if not self._item:
            raise Unavailable("the system status bar refused a new item")
        rt.send(self._item, "retain")

        self._apply_icon()
        self._apply_menu()
        self._run_loop()

    def _run_loop(self) -> None:
        rt = self.rt
        date_cls = rt.cls("NSDate")
        run_loop = rt.send(rt.cls("NSRunLoop"), "currentRunLoop")
        mode = self._nsstring("kCFRunLoopDefaultMode")
        import time

        while not self._stopped:
            until = rt.send(date_cls, "dateWithTimeIntervalSinceNow:",
                            ctypes.c_double(0.3), argtypes=[ctypes.c_double])
            rt.send(run_loop, "runMode:beforeDate:", mode, until,
                    restype=ctypes.c_bool, argtypes=[objc_id, objc_id])

            now = time.monotonic()
            for seconds, callback, due in list(self._timers):
                if now >= due[0]:
                    due[0] = now + seconds
                    try:
                        if callback() is False:
                            self._timers = [t for t in self._timers
                                            if t[1] is not callback]
                    except Exception:
                        pass

    def stop(self) -> None:
        self._stopped = True

    def every(self, seconds: int, callback: Callable[[], bool]) -> None:
        import time
        self._timers.append((seconds, callback, [time.monotonic() + seconds]))


    def _nsstring(self, text: str):
        rt = self.rt
        return rt.send(rt.cls("NSString"), "stringWithUTF8String:",
                       text.encode(), argtypes=[ctypes.c_char_p])

    def _apply_icon(self) -> None:
        rt = self.rt
        png = icon.render()

        data = rt.send(rt.cls("NSData"), "dataWithBytes:length:",
                       png, ctypes.c_ulong(len(png)),
                       argtypes=[ctypes.c_char_p, ctypes.c_ulong])
        image = rt.send(rt.send(rt.cls("NSImage"), "alloc"),
                        "initWithData:", data, argtypes=[objc_id])
        if not image:
            return

        size = getattr(icon, "SIZE", 32) / 2.0
        rt.send(image, "setSize:", _NSSize(size, size), argtypes=[_NSSize])
        rt.send(image, "setTemplate:", ctypes.c_bool(False),
                restype=None, argtypes=[ctypes.c_bool])

        button = rt.send(self._item, "button")
        if button:
            rt.send(button, "setImage:", image, restype=None, argtypes=[objc_id])
            rt.send(button, "setToolTip:", self._nsstring(self.owner.title),
                    restype=None, argtypes=[objc_id])
        else:
            rt.send(self._item, "setImage:", image, restype=None, argtypes=[objc_id])

    def _apply_menu(self) -> None:
        rt = self.rt
        menu = rt.send(rt.send(rt.cls("NSMenu"), "alloc"), "init")
        rt.send(menu, "setAutoenablesItems:", ctypes.c_bool(False),
                restype=None, argtypes=[ctypes.c_bool])

        for index, item in enumerate(self.owner.flattened()):
            entry = rt.send(
                rt.send(rt.cls("NSMenuItem"), "alloc"),
                "initWithTitle:action:keyEquivalent:",
                self._nsstring(item.label), None, self._nsstring(""),
                argtypes=[objc_id, SEL, objc_id])

            rt.send(entry, "setEnabled:", ctypes.c_bool(True),
                    restype=None, argtypes=[ctypes.c_bool])
            target = self._make_target(index)
            rt.send(entry, "setTarget:", target, restype=None, argtypes=[objc_id])
            rt.send(entry, "setAction:", rt.sel("invoke:"),
                    restype=None, argtypes=[SEL])
            rt.send(menu, "addItem:", entry, restype=None, argtypes=[objc_id])

        rt.send(self._item, "setMenu:", menu, restype=None, argtypes=[objc_id])

    def _make_target(self, index: int):
        rt = self.rt
        name = f"XeniaTarget{index}_{id(self):x}".encode()
        cls = rt.objc.objc_allocateClassPair(rt.cls("NSObject"), name, 0)
        if not cls:
            cls = rt.cls(name.decode())

        prototype = ctypes.CFUNCTYPE(None, objc_id, SEL, objc_id)

        def handler(_self, _sel, _sender, row=index):
            self.owner.click(row + 1)

        callback = prototype(handler)
        rt.objc.class_addMethod(cls, rt.sel("invoke:"),
                                ctypes.cast(callback, ctypes.c_void_p), b"v@:@")
        rt.objc.objc_registerClassPair(cls)

        target = rt.send(rt.send(cls, "alloc"), "init")
        self._callbacks.append(callback)
        self._targets.append(target)
        return target


class _NSSize(ctypes.Structure):
    _fields_ = [("width", ctypes.c_double), ("height", ctypes.c_double)]

    def __init__(self, width: float, height: float) -> None:
        super().__init__(width, height)


def available() -> bool:
    if sys.platform != "darwin":
        return False
    try:
        return ctypes.util.find_library("objc") is not None
    except Exception:
        return False
