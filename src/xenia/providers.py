from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import threading
import time
from typing import Any, NamedTuple

from . import config

PROTOCOL = 1
RESIDENT_PROTOCOL = 2
OUTPUT_LIMIT = 1 << 20
MAX_WORKERS = 16
MAX_BACKOFF_S = 30.0
TIMINGS_KEPT = 1000


class ProviderError(Exception):
    def __init__(self, message: str, code: str = "unavailable") -> None:
        super().__init__(message)
        self.code = code


class ProviderRefusal(ProviderError):
    pass


class Resident(NamedTuple):
    command: tuple[str, ...]
    timeout: float
    request_timeout: float
    workers: int
    files: tuple[str, ...]
    digest: str


def configured() -> dict[str, Any]:
    held = config.site().get("signing_providers", {})
    if not isinstance(held, dict):
        return {}
    return {name: value for name, value in held.items()
            if isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name)}


def _settings(name: str) -> tuple[list[str], float]:
    held = configured().get(name)
    if not isinstance(held, dict):
        raise ProviderError(f"signing provider '{name}' needs a command")
    command = held.get("command")
    timeout = held.get("timeout_s", 15)
    if (not isinstance(command, list) or not command
            or any(not isinstance(arg, str) or not arg or "\x00" in arg for arg in command)
            or not os.path.isabs(command[0])):
        raise ProviderError(f"signing provider '{name}' needs an absolute executable and an argument list")
    if type(timeout) not in (int, float) or not 0 < timeout <= 120:
        raise ProviderError(f"signing provider '{name}' timeout_s must be greater than zero and at most 120")
    if not os.path.isfile(command[0]) or not os.access(command[0], os.X_OK):
        raise ProviderError(f"signing provider '{name}' executable is unavailable")
    _pin_of(name, held)
    _resident_of(name, held)
    return command, float(timeout)


def _pin_of(name: str, held: dict[str, Any]) -> tuple[tuple[str, ...], str]:
    files, digest = held.get("files"), held.get("sha256")
    if files is None and digest is None:
        return (), ""
    if (not isinstance(files, list) or not files
            or any(not isinstance(path, str) or "\x00" in path or not os.path.isabs(path) for path in files)
            or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
        raise ProviderError(f"signing provider '{name}' pin needs absolute files and a sha256")
    return tuple(files), digest


def _resident_of(name: str, held: dict[str, Any]) -> tuple[float, int] | None:
    resident = held.get("resident", False)
    if type(resident) is not bool:
        raise ProviderError(f"signing provider '{name}' resident must be true or false")
    workers = held.get("workers", 1)
    request_timeout = held.get("request_timeout_s", 5)
    if type(workers) is not int or not 1 <= workers <= MAX_WORKERS:
        raise ProviderError(f"signing provider '{name}' workers must be from 1 to {MAX_WORKERS}")
    if type(request_timeout) not in (int, float) or not 0 < request_timeout <= 120:
        raise ProviderError(
            f"signing provider '{name}' request_timeout_s must be greater than zero and at most 120")
    if not resident:
        return None
    return float(request_timeout), workers


def _resident_settings(name: str) -> Resident | None:
    command, timeout = _settings(name)
    held = configured()[name]
    shape = _resident_of(name, held)
    if shape is None:
        return None
    files, digest = _pin_of(name, held)
    return Resident(tuple(command), timeout, shape[0], shape[1], files, digest)


def _entries(path: str, seen: set[str]):
    real = os.path.realpath(path)
    try:
        mode = os.stat(real).st_mode
    except OSError as exc:
        raise ProviderError("signing provider pinned file is missing") from exc
    if stat.S_ISREG(mode):
        yield "F", path, real
    elif not stat.S_ISDIR(mode):
        raise ProviderError("signing provider pinned files must be regular files or directories")
    elif real in seen:
        yield "S", path, real
    else:
        seen.add(real)
        yield "D", path, real
        for name in sorted(os.listdir(real)):
            yield from _entries(os.path.join(path, name), seen)


def _contents(real: str) -> bytes:
    descriptor = os.open(real, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ProviderError("signing provider pinned files must be regular files or directories")
        single = hashlib.sha256()
        for block in iter(lambda: handle.read(1 << 20), b""):
            single.update(block)
    return single.digest()


def digest(files) -> str:
    total = hashlib.sha256()
    seen: set[str] = set()
    for root in sorted(files):
        for kind, path, real in _entries(root, seen):
            contents = _contents(real) if kind == "F" else b""
            total.update(kind.encode() + b"\0" + os.fsencode(path) + b"\0" + os.fsencode(real)
                         + b"\0" + contents + b"\0")
    return total.hexdigest()


def _check_pin(files: tuple[str, ...], expected: str) -> None:
    if not files:
        return
    try:
        found = digest(files)
    except OSError as exc:
        raise ProviderError("signing provider pinned files cannot be read") from exc
    if found != expected:
        raise ProviderError("signing provider files changed since they were pinned")


def available(name: str) -> bool:
    try:
        _settings(name)
        return True
    except ProviderError:
        return False


def _exchange(command: list[str], payload: bytes, timeout: float) -> bytes:
    try:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, cwd="/", start_new_session=True)
    except OSError as exc:
        raise ProviderError("signing provider could not be started") from exc
    output = bytearray()
    deadline = time.monotonic() + timeout
    remaining = memoryview(payload)
    try:
        with selectors.DefaultSelector() as streams:
            for pipe, event in ((process.stdin, selectors.EVENT_WRITE),
                                (process.stdout, selectors.EVENT_READ)):
                os.set_blocking(pipe.fileno(), False)
                streams.register(pipe, event)
            while streams.get_map():
                left = deadline - time.monotonic()
                if left <= 0:
                    raise ProviderError("signing provider timed out")
                for key, event in streams.select(left):
                    pipe = key.fileobj
                    try:
                        if event & selectors.EVENT_WRITE:
                            try:
                                written = os.write(pipe.fileno(), remaining[:65536])
                                remaining = remaining[written:]
                            except BrokenPipeError:
                                remaining = memoryview(b"")
                            if not remaining:
                                streams.unregister(pipe)
                                pipe.close()
                        else:
                            chunk = os.read(pipe.fileno(), 65536)
                            if not chunk:
                                streams.unregister(pipe)
                                pipe.close()
                            output.extend(chunk)
                            if len(output) > OUTPUT_LIMIT:
                                raise ProviderError("signing provider response is too large")
                    except BlockingIOError:
                        continue
        status = process.wait(timeout=max(0, deadline - time.monotonic()))
        if status:
            raise ProviderError("signing provider failed")
        return bytes(output)
    except subprocess.TimeoutExpired as exc:
        raise ProviderError("signing provider timed out") from exc
    except OSError as exc:
        raise ProviderError("signing provider communication failed") from exc
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        for pipe in (process.stdin, process.stdout):
            pipe.close()


def invoke(name: str, request: dict[str, Any]) -> tuple[str, dict[str, str]]:
    command, timeout = _settings(name)
    resident = _resident_settings(name)
    if resident is not None:
        return _pool(resident).call(request)
    try:
        payload = json.dumps({**request, "protocol": PROTOCOL}, allow_nan=False).encode() + b"\n"
    except (TypeError, ValueError) as exc:
        raise ProviderError("signing provider input must be JSON", code="off-policy") from exc
    _check_pin(*_pin_of(name, configured()[name]))
    raw = _exchange(command, payload, timeout)
    try:
        reply = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ProviderError("signing provider returned invalid JSON") from exc
    return _answer(reply, PROTOCOL)


def _answer(reply: Any, protocol: int, extra: frozenset[str] = frozenset()) -> tuple[str, dict[str, str]]:
    if not isinstance(reply, dict) or type(reply.get("protocol")) is not int or reply["protocol"] != protocol:
        raise ProviderError("signing provider returned an unsupported protocol")
    if "refused" in reply:
        reason, code = reply["refused"], reply.get("code", "off-policy")
        if (set(reply) - {"protocol", "refused", "code"} - extra or not isinstance(reason, str)
                or not reason or code not in ("off-policy", "unavailable")):
            raise ProviderError("signing provider returned an invalid refusal")
        raise ProviderRefusal(reason, code=code)
    signature, headers = reply.get("signature"), reply.get("headers", {})
    if (set(reply) - {"protocol", "signature", "headers"} - extra
            or not isinstance(signature, str) or not signature or not isinstance(headers, dict)):
        raise ProviderError("signing provider returned an invalid signature response")
    for key, value in headers.items():
        if (not isinstance(key, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key)
                or not isinstance(value, str) or "\r" in value or "\n" in value):
            raise ProviderError("signing provider returned invalid headers")
    return signature, headers


def _wait(fd: int, event: int, deadline: float) -> bool:
    left = deadline - time.monotonic()
    if left <= 0:
        raise ProviderError("signing provider timed out")
    with selectors.DefaultSelector() as streams:
        streams.register(fd, event)
        return bool(streams.select(left))


class _Worker:
    def __init__(self, settings: Resident) -> None:
        self.settings = settings
        self.process: subprocess.Popen | None = None
        self.pending = bytearray()
        self.started_at: float | None = None

    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def start(self, deadline: float) -> None:
        self.stop()
        _check_pin(self.settings.files, self.settings.digest)
        try:
            self.process = subprocess.Popen(list(self.settings.command), stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                            cwd="/", start_new_session=True)
        except OSError as exc:
            self.process = None
            raise ProviderError("signing provider could not be started") from exc
        os.set_blocking(self.process.stdin.fileno(), False)
        os.set_blocking(self.process.stdout.fileno(), False)
        self.pending = bytearray()
        ready = self.read(deadline)
        if ready != {"protocol": RESIDENT_PROTOCOL, "ready": True}:
            raise ProviderError("signing provider did not report ready")
        self.started_at = time.time()

    def write(self, data: bytes, deadline: float) -> None:
        fd = self.process.stdin.fileno()
        remaining = memoryview(data)
        while remaining:
            if not _wait(fd, selectors.EVENT_WRITE, deadline):
                continue
            try:
                written = os.write(fd, remaining[:65536])
            except BlockingIOError:
                continue
            except OSError as exc:
                raise ProviderError("signing provider communication failed") from exc
            remaining = remaining[written:]

    def read(self, deadline: float) -> Any:
        fd = self.process.stdout.fileno()
        while b"\n" not in self.pending:
            if len(self.pending) > OUTPUT_LIMIT:
                raise ProviderError("signing provider response is too large")
            if not _wait(fd, selectors.EVENT_READ, deadline):
                continue
            try:
                chunk = os.read(fd, 65536)
            except BlockingIOError:
                continue
            except OSError as exc:
                raise ProviderError("signing provider communication failed") from exc
            if not chunk:
                raise ProviderError("signing provider exited")
            self.pending.extend(chunk)
        line, _, rest = bytes(self.pending).partition(b"\n")
        self.pending = bytearray(rest)
        if len(line) > OUTPUT_LIMIT:
            raise ProviderError("signing provider response is too large")
        try:
            return json.loads(line.decode("utf-8"))
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise ProviderError("signing provider returned invalid JSON") from exc

    def stop(self) -> None:
        process, self.process, self.started_at = self.process, None, None
        if process is None:
            return
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        for pipe in (process.stdin, process.stdout):
            try:
                pipe.close()
            except OSError:
                pass


class _Pool:
    def __init__(self, settings: Resident) -> None:
        self.settings = settings
        self.workers = [_Worker(settings) for _ in range(settings.workers)]
        self.idle = list(self.workers)
        self.free = threading.Condition()
        self.failures = 0
        self.retry_at = 0.0
        self.sequence = 0
        self.served = 0
        self.faults = 0
        self.timings: list[float] = []
        self.closed = False

    def _take(self, deadline: float) -> tuple[_Worker, int]:
        with self.free:
            while not self.idle:
                left = deadline - time.monotonic()
                if left <= 0 or self.closed:
                    raise ProviderError("signing provider is busy")
                self.free.wait(left)
            if self.closed:
                raise ProviderError("signing provider is stopping")
            self.sequence += 1
            return self.idle.pop(), self.sequence

    def _give(self, worker: _Worker) -> None:
        with self.free:
            self.idle.append(worker)
            self.free.notify()

    def _fault(self, worker: _Worker) -> None:
        worker.stop()
        with self.free:
            self.failures += 1
            self.faults += 1
            self.retry_at = time.monotonic() + min(MAX_BACKOFF_S, 2.0 ** (self.failures - 1))

    def _ready(self, worker: _Worker) -> None:
        if worker.running():
            return
        with self.free:
            waiting = self.retry_at - time.monotonic()
        if waiting > 0:
            raise ProviderError(f"signing provider is restarting; it is retried in {waiting:.1f}s")
        try:
            worker.start(time.monotonic() + self.settings.timeout)
        except ProviderError:
            self._fault(worker)
            raise

    def warm(self) -> None:
        for _ in range(len(self.workers)):
            try:
                worker, _ = self._take(time.monotonic() + self.settings.timeout)
            except ProviderError:
                return
            try:
                self._ready(worker)
            except ProviderError:
                pass
            finally:
                self._give(worker)

    def call(self, request: dict[str, Any]) -> tuple[str, dict[str, str]]:
        worker, ident = self._take(time.monotonic() + self.settings.request_timeout)
        try:
            try:
                line = json.dumps({**request, "protocol": RESIDENT_PROTOCOL, "id": ident},
                                  allow_nan=False).encode() + b"\n"
            except (TypeError, ValueError) as exc:
                raise ProviderRefusal("signing provider input must be JSON", code="off-policy") from exc
            self._ready(worker)
            started = time.monotonic()
            deadline = started + self.settings.request_timeout
            try:
                worker.write(line, deadline)
                reply = worker.read(deadline)
                if not isinstance(reply, dict) or type(reply.get("id")) is not int or reply["id"] != ident:
                    raise ProviderError("signing provider answered another request")
                answer = _answer(reply, RESIDENT_PROTOCOL, frozenset({"id"}))
            except ProviderRefusal:
                self._served(started)
                raise
            except ProviderError:
                self._fault(worker)
                raise
            self._served(started)
            return answer
        finally:
            self._give(worker)

    def _served(self, started: float) -> None:
        with self.free:
            self.failures = 0
            self.served += 1
            self.timings.append((time.monotonic() - started) * 1000)
            del self.timings[:-TIMINGS_KEPT]

    def close(self) -> None:
        with self.free:
            self.closed = True
            self.free.notify_all()
        for worker in self.workers:
            worker.stop()

    def status(self) -> dict[str, Any]:
        with self.free:
            timings = sorted(self.timings)
            running = [w for w in self.workers if w.running()]
            return {"resident": True, "workers": len(self.workers), "running": len(running),
                    "pids": [w.process.pid for w in running],
                    "started_at": min((w.started_at for w in running if w.started_at), default=None),
                    "served": self.served, "faults": self.faults,
                    "p50_ms": round(timings[len(timings) // 2], 3) if timings else None,
                    "p99_ms": round(timings[min(len(timings) - 1, int(len(timings) * 0.99))], 3)
                    if timings else None,
                    "retry_in_s": max(0.0, round(self.retry_at - time.monotonic(), 1))}


_pools: dict[Resident, _Pool] = {}
_pools_lock = threading.Lock()


def _pool(settings: Resident) -> _Pool:
    with _pools_lock:
        pool = _pools.get(settings)
        if pool is None or pool.closed:
            pool = _pools[settings] = _Pool(settings)
        return pool


def start() -> None:
    for name in sorted(configured()):
        try:
            settings = _resident_settings(name)
        except ProviderError:
            continue
        if settings is not None:
            threading.Thread(target=_pool(settings).warm, daemon=True, name="xenia-provider-start").start()


def stop() -> None:
    with _pools_lock:
        pools = list(_pools.values())
        _pools.clear()
    for pool in pools:
        pool.close()


def status() -> dict[str, dict[str, Any]]:
    found = {}
    for name in sorted(configured()):
        try:
            settings = _resident_settings(name)
        except ProviderError as exc:
            found[name] = {"error": str(exc)}
            continue
        if settings is None:
            continue
        with _pools_lock:
            pool = _pools.get(settings)
        found[name] = pool.status() if pool is not None else {"resident": True, "workers": settings.workers,
                                                              "running": 0}
    return found
