"""First-use setup for the credential store, and the commands that drive it.

Getting a store that works — find what is serving one, prove it can hold a
value, install the user's choice if nothing is — and the small CLI for
entering credentials and approving their use. Nothing here ever puts a value
on a command line.
"""

from __future__ import annotations

import getpass
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import config, db, vault

# --------------------------------------------------------------------------
# Probing
# --------------------------------------------------------------------------

#: What a user can pick when nothing is serving a store, in the order offered.
CLIENTS: dict[str, dict[str, Any]] = {
    "gnome-keyring": {
        "label": "the desktop keyring (gnome-keyring)",
        "why": "unlocked by your login, nothing else to run",
        "packages": {"apt": "gnome-keyring", "dnf": "gnome-keyring",
                     "pacman": "gnome-keyring", "zypper": "gnome-keyring",
                     "brew": None},
    },
    "keepassxc": {
        "label": "KeePassXC",
        "why": "a database file you own, unlocked by a password or a key file",
        "packages": {"apt": "keepassxc", "dnf": "keepassxc",
                     "pacman": "keepassxc", "zypper": "keepassxc",
                     "brew": "keepassxc"},
    },
}

MANAGERS = (
    ("apt", ["sudo", "apt", "install", "-y"]),
    ("dnf", ["sudo", "dnf", "install", "-y"]),
    ("pacman", ["sudo", "pacman", "-S", "--noconfirm"]),
    ("zypper", ["sudo", "zypper", "install", "-y"]),
    ("brew", ["brew", "install"]),
)


def package_manager() -> tuple[str, list[str]] | tuple[None, None]:
    for name, argv in MANAGERS:
        if shutil.which(name):
            return name, argv
    return None, None


def probe() -> dict[str, Any]:
    """What is serving a credential store here, and does it work.

    The self-test is the part that matters: a provider can own the bus name,
    advertise a collection and still refuse to store, and a listing would
    report all of that as fine.
    """
    store = None
    out: dict[str, Any] = {"platform": sys.platform,
                           "backend": None, "provider": None,
                           "available": False, "selftest": None}
    try:
        store = vault.backend()
    except vault.VaultError as exc:
        out["detail"] = str(exc)
        return out

    out["backend"] = store.kind
    described = store.describe()
    out["provider"] = described.get("provider")
    out["available"] = bool(described.get("available"))
    out["detail"] = described.get("detail")
    if out["available"]:
        out["selftest"] = vault.selftest(store)
    return out


def keepassxc_config() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return Path(base) / "keepassxc" / "keepassxc.ini"


def keepassxc_state(path: Path | None = None) -> dict[str, Any]:
    """What KeePassXC still needs before it can serve the Secret Service."""
    path = path or keepassxc_config()
    text = path.read_text(errors="replace") if path.exists() else ""
    section = re.search(r"^\[FdoSecrets\](.*?)(?=^\[|\Z)", text,
                        re.S | re.M)
    body = section.group(1) if section else ""
    return {
        "path": str(path),
        "installed": bool(shutil.which("keepassxc")),
        "config_exists": path.exists(),
        "fdo_enabled": bool(re.search(r"^Enabled\s*=\s*true", body,
                                      re.I | re.M)),
        "exposed_group": bool(re.search(r"^ExposedGroup\s*=", body,
                                        re.I | re.M)),
        "autostart": autostart_path().exists(),
    }


def autostart_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return Path(base) / "autostart" / "keepassxc.desktop"


def enable_keepassxc_fdo(path: Path | None = None) -> str:
    """Turn on KeePassXC's Secret Service integration in its own config.

    Only ever reached from an explicit `--wire`: writing another program's
    configuration is not something to do quietly.
    """
    path = path or keepassxc_config()
    path.parent.mkdir(parents=True, exist_ok=True)
    text = path.read_text(errors="replace") if path.exists() else ""

    if re.search(r"^\[FdoSecrets\]", text, re.M):
        if re.search(r"^Enabled\s*=", text, re.I | re.M):
            text = re.sub(r"^Enabled\s*=.*$", "Enabled=true", text,
                          count=1, flags=re.I | re.M)
        else:
            text = re.sub(r"^\[FdoSecrets\]\s*$", "[FdoSecrets]\nEnabled=true",
                          text, count=1, flags=re.M)
    else:
        text = text.rstrip("\n") + "\n\n[FdoSecrets]\nEnabled=true\n"
        text = text.lstrip("\n")

    path.write_text(text)
    return str(path)


def write_autostart() -> str:
    target = autostart_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=KeePassXC\n"
        "Comment=Started by xenia so the credential store answers\n"
        "Exec=keepassxc\n"
        "Terminal=false\n"
        "X-GNOME-Autostart-enabled=true\n")
    return str(target)


# --------------------------------------------------------------------------
# `xenia secrets setup`
# --------------------------------------------------------------------------

def setup(argv: list[str]) -> int:
    wire = "--wire" in argv
    install_only = _flag_value(argv, "--install")

    print("Credential store\n")
    found = probe()

    print(f"  platform    {found['platform']}")
    print(f"  store       {found['backend'] or 'none available'}")
    if found.get("provider"):
        print(f"  served by   {found['detail']}")
    elif found.get("detail"):
        print(f"  served by   {found['detail']}")

    check = found.get("selftest")
    if check:
        print(f"  self-test   {'passed' if check['ok'] else 'FAILED'} — "
              f"{check.get('detail', '')}")

    if check and check["ok"] and not (wire or install_only):
        print("\n  Ready. Add a credential with:\n"
              "    xenia secret new\n")
        return 0

    if install_only:
        return _install(install_only)

    if not found["available"]:
        print("\n  Nothing is serving a credential store on this session.\n")
        _offer()
        return 1

    if check and not check["ok"]:
        print("\n  A store answered but could not hold a value. If that is "
              "KeePassXC, the\n  database may be locked, or no group is "
              "exposed to the Secret Service.\n")

    state = keepassxc_state()
    if state["installed"]:
        _keepassxc_report(state, wire=wire)
    return 0 if (check and check["ok"]) else 1


def _offer() -> None:
    manager, argv = package_manager()
    print("  Choose one and xenia will show you how to install it:\n")
    for key, client in CLIENTS.items():
        package = client["packages"].get(manager or "")
        line = f"    {key:14} {client['label']} — {client['why']}"
        print(line)
        if package and argv:
            print(f"                   xenia secrets setup --install {key}")
    print()
    if manager is None:
        print("  No package manager xenia recognises "
              f"({', '.join(name for name, _ in MANAGERS)}).\n")
    _conflict_note()


def _conflict_note() -> None:
    print("  Note: only one program can own org.freedesktop.secrets. If you "
          "enable\n  KeePassXC's Secret Service integration while "
          "gnome-keyring already holds\n  the name, KeePassXC loses and says "
          "so only in its own settings dialog.\n")


def _install(choice: str) -> int:
    client = CLIENTS.get(choice)
    if client is None:
        print(f"xenia: no such client '{choice}' — "
              f"{', '.join(CLIENTS)}", file=sys.stderr)
        return 2

    manager, argv = package_manager()
    package = client["packages"].get(manager or "") if manager else None
    if not package or not argv:
        print(f"xenia: no package for {choice} with "
              f"{manager or 'any known package manager'} — install it "
              f"yourself, then re-run `xenia secrets setup`.", file=sys.stderr)
        return 2

    command = argv + [package]
    print(f"  {' '.join(command)}\n")
    if not sys.stdin.isatty():
        print("  Not a terminal — run that yourself. xenia will not install "
              "software\n  from a background service.", file=sys.stderr)
        return 1
    if input("  Run it now? [y/N] ").strip().lower() not in ("y", "yes"):
        print("  Left alone.")
        return 0

    done = subprocess.run(command)
    if done.returncode != 0:
        return done.returncode
    print("\n  Installed. Re-run `xenia secrets setup` once it is running.")
    if choice == "keepassxc":
        print("  KeePassXC needs a database before it can serve anything — "
              "make one in\n  its own first-run wizard, then "
              "`xenia secrets setup --wire`.")
    return 0


def _keepassxc_report(state: dict, *, wire: bool) -> None:
    print("\n  KeePassXC\n")
    print(f"    config      {state['path']}")
    print(f"    integration {'on' if state['fdo_enabled'] else 'OFF'}")
    print(f"    exposed grp {'set' if state['exposed_group'] else 'not set'}")
    print(f"    autostart   {'yes' if state['autostart'] else 'no'}")

    if not wire:
        todo = []
        if not state["fdo_enabled"]:
            todo.append("enable Settings → Secret Service Integration")
        if not state["exposed_group"]:
            todo.append("expose a group to it, in the same dialog")
        if not state["autostart"]:
            todo.append("start it with your session")
        if todo:
            print("\n    Still to do: " + "; ".join(todo))
            print("    `xenia secrets setup --wire` will do the first and "
                  "the last for you.\n"
                  "    Exposing a group has to happen in KeePassXC, because "
                  "it is a choice\n    about which of your passwords xenia "
                  "can see.")
        return

    if not state["fdo_enabled"]:
        print(f"\n    enabled integration in {enable_keepassxc_fdo()}")
    if not state["autostart"]:
        print(f"    autostart written to {write_autostart()}")
    print("    Restart KeePassXC, expose a group in Settings → Secret "
          "Service Integration,\n    then re-run `xenia secrets setup`.")


# --------------------------------------------------------------------------
# The dialogue: a terminal window, because the value is typed and not echoed
# --------------------------------------------------------------------------

#: How each terminal wants to be told what to run. The conventions differ, so
#: a known one is preferred over the generic alternative.
TERMINALS = (
    ("xfce4-terminal", ["-x"]),
    ("gnome-terminal", ["--"]),
    ("konsole", ["-e"]),
    ("alacritty", ["-e"]),
    ("kitty", ["-e"]),
    ("foot", ["-e"]),
    ("xterm", ["-e"]),
    ("x-terminal-emulator", ["-e"]),
)


def terminal_for(command: list[str]) -> list[str] | None:
    for name, flag in TERMINALS:
        found = shutil.which(name)
        if found:
            return [found, *flag, *command]
    return None


def open_in_terminal(command: list[str]) -> bool:
    """Run a command in a window of its own. False when there is nowhere to."""
    if sys.platform == "darwin":
        script = " ".join(shlex.quote(part) for part in command)
        try:
            subprocess.Popen(
                ["osascript", "-e",
                 f'tell application "Terminal" to do script "{script}"'],
                start_new_session=True)
            return True
        except OSError:
            return False

    argv = terminal_for(command)
    if argv is None or not os.environ.get("DISPLAY") and not os.environ.get(
            "WAYLAND_DISPLAY"):
        return False
    try:
        subprocess.Popen(argv, start_new_session=True)
        return True
    except OSError:
        return False


def entry_point() -> str:
    from . import app
    return str(app._entry_point())


def open_dialogue() -> bool:
    """What the tray's Credentials → Add… does: setup if needed, then add one."""
    return open_in_terminal([entry_point(), "secret", "new"])


def _ask(prompt: str, default: str = "") -> str:
    shown = f"{prompt} [{default}]: " if default else f"{prompt}: "
    try:
        answer = input(shown).strip()
    except EOFError:
        return default
    return answer or default


def _ask_yes(prompt: str, default: bool = True) -> bool:
    answer = _ask(f"{prompt} [{'Y/n' if default else 'y/N'}]").lower()
    if not answer:
        return default
    return answer.startswith("y")


def wizard(argv: list[str]) -> int:
    """Add and scope one credential, interactively.

    A terminal rather than a window: the value has to be typed without being
    echoed, and everything this does is already a command.
    """
    from . import broker

    if not sys.stdin.isatty():
        print("xenia: `secret new` is interactive — run it in a terminal, or "
              "use `xenia secret add NAME`.", file=sys.stderr)
        return 2

    print("\nAdd a credential to xenia\n" + "-" * 26)
    found = probe()
    check = found.get("selftest")
    if not (check and check["ok"]):
        print("\nFirst, somewhere to keep it.\n")
        if setup([]) != 0:
            print("\nNothing can be stored until that is sorted. Nothing was "
                  "changed.", file=sys.stderr)
            return 1
        print()
    else:
        print(f"  store       {found['detail']}\n")

    conn = db.connect()
    try:
        name = ""
        while not name:
            name = _ask("Name for it (e.g. gitlab-pat)")
        existing = broker.entry(conn, name)
        if existing is not None:
            allowed = json.loads(existing["hosts"])
            print(f"  '{name}' already exists"
                  + (f", allowed at {', '.join(allowed)}." if allowed
                     else ", not yet allowed anywhere."))
            if not _ask_yes("Replace it?", default=False):
                return 0

        print()
        try:
            value = read_value(name)
        except (ValueError, EOFError, KeyboardInterrupt) as exc:
            print(f"\nxenia: {exc or 'cancelled'} — nothing was changed.",
                  file=sys.stderr)
            return 1
        try:
            vault.backend().set(name, value)
        except vault.VaultError as exc:
            print(f"xenia: {exc} — nothing was changed.", file=sys.stderr)
            return 1
        del value

        try:
            broker.register(conn, name)
        except ValueError as exc:
            print(f"xenia: {exc}", file=sys.stderr)
            return 2

        print(f"\n  Stored '{name}' in the {vault.configured_kind()}.")
        print("\n  Nothing can use it yet, and you do not have to say where "
              "it may go.\n  The first time something reaches for it you "
              "will be asked, and the\n  answer is what decides where it "
              "can be used from then on.\n")
        print("  See what it has been allowed with `xenia secret list`, or "
              "in the\n  report's Credentials tab — the tray's Credentials → "
              "List.\n")
    finally:
        conn.close()

    if sys.stdin.isatty():
        _ask("Press enter to close")
    return 0


# --------------------------------------------------------------------------
# Adding, renaming and removing one: what every front end does through here
# --------------------------------------------------------------------------

def add(conn, name: str, value: str, **policy) -> dict:
    """Put a value in the store and register the policy beside it.

    What `xenia secret add`, the wizard and the report page all end up in, so
    that a credential entered from the tray and one entered in the browser are
    the same thing afterwards.

    The policy is checked before either half happens — a typo in it would
    otherwise leave a value in the keyring with nothing here to describe it —
    and the value goes in before the policy, so a store that refuses cannot
    leave a widened policy in force over the value that is still there.
    """
    from . import broker

    name = (name or "").strip()
    if not name:
        raise ValueError("a credential needs a name")
    if not value:
        raise ValueError(f"no value given for '{name}' — nothing was changed")
    broker.methods_for(policy.get("methods"))

    vault.backend().set(name, value)
    del value
    return broker.register(conn, name, **policy)


def remove(conn, name: str) -> dict:
    """Forget a credential: the policy here, and the value in the OS store.

    Both halves are reported because either can be the only one there. A
    cancelled add leaves a value with no policy, and a value deleted from the
    keyring by hand leaves a policy over nothing.
    """
    from . import broker

    name = (name or "").strip()
    out = {"name": name, "policy": broker.forget(conn, name), "value": False,
           "store_error": None}
    try:
        out["value"] = bool(vault.backend().delete(name))
    except vault.VaultError as exc:
        out["store_error"] = str(exc)
    return out


def rename(conn, name: str, to: str) -> dict:
    """Move a credential, value and all, to a different name.

    The value goes to the new name first and only leaves the old one once the
    policy has followed it: a value under a name with no policy is an orphan
    the list flags and `secret rm` clears, where a policy with no value is a
    credential that has quietly stopped working.

    Anything that writes `{{secret:NAME}}` is naming the old one, so this
    reports what to change them to.
    """
    from . import broker

    name = (name or "").strip()
    to = (to or "").strip()
    if not to:
        raise ValueError("a credential needs a name")
    if to == name:
        raise ValueError(f"'{name}' is already its name")
    if broker.entry(conn, name) is None:
        raise ValueError(f"no credential called '{name}'")
    if broker.entry(conn, to) is not None:
        raise ValueError(f"there is already a credential called '{to}'")

    store = vault.backend()
    held = store.get(name)
    moved = held is not None
    if moved:
        store.set(to, held)
    del held

    try:
        broker.rename(conn, name, to)
    except Exception:
        if moved:
            try:
                store.delete(to)
            except vault.VaultError:
                pass
        raise

    out = {"name": name, "to": to, "value": moved, "store_error": None}
    try:
        store.delete(name)
    except vault.VaultError as exc:
        out["store_error"] = str(exc)
    return out


def stored_names() -> set[str]:
    """What the store holds, or nothing if it will not say."""
    try:
        return set(vault.backend().names())
    except Exception:
        return set()


# --------------------------------------------------------------------------
# `xenia secret …`
# --------------------------------------------------------------------------

def _flag_value(argv: list[str], flag: str) -> str | None:
    if flag in argv:
        index = argv.index(flag)
        if index + 1 < len(argv):
            return argv[index + 1]
    for item in argv:
        if item.startswith(flag + "="):
            return item.split("=", 1)[1]
    return None


def _flag_values(argv: list[str], flag: str) -> list[str]:
    out = []
    for index, item in enumerate(argv):
        if item == flag and index + 1 < len(argv):
            out.append(argv[index + 1])
        elif item.startswith(flag + "="):
            out.append(item.split("=", 1)[1])
    return out


def read_value(name: str) -> str:
    """Take a credential from a terminal, or from a pipe. Never from argv."""
    if not sys.stdin.isatty():
        return sys.stdin.read().strip()
    first = getpass.getpass(f"Value for '{name}' (not echoed): ").strip()
    if not first:
        raise ValueError("empty")
    again = getpass.getpass("Again: ").strip()
    if first != again:
        raise ValueError("those did not match")
    return first


def duration(text: str) -> float:
    match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([smhd]?)", text.strip().lower())
    if not match:
        raise ValueError(f"not a duration: {text} (try 30m, 4h, 2d)")
    size = float(match.group(1))
    return size * {"": 60, "s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)]


def main(argv: list[str]) -> int:
    from . import broker

    command, rest = argv[0], argv[1:]

    if command == "secrets":
        # `secrets` is the store; `secret` is one credential. Typing the
        # plural for a singular verb used to silently run setup.
        if not rest or rest[0] == "setup":
            return setup(rest[1:] if rest else [])
        if rest[0] in ("help", "-h", "--help"):
            return _usage()
        return main(["secret", *rest])

    conn = db.connect()
    try:
        if command == "secret":
            return _secret(conn, broker, rest)
        if command == "grant":
            return _grant(conn, broker, rest)
        if command == "grants":
            return _grants(conn, broker, "--all" in rest)
        if command == "revoke":
            if not rest:
                print("xenia: revoke which credential?", file=sys.stderr)
                return 2
            count = broker.revoke(conn, rest[0], _flag_value(rest, "--host"))
            print(f"Revoked {count} grant(s) for {rest[0]}.")
            return 0
    finally:
        conn.close()
    return _usage()


def _secret(conn, broker, argv: list[str]) -> int:
    if not argv:
        return _list(conn, broker)
    action, rest = argv[0], argv[1:]

    if action == "list":
        code = _list(conn, broker)
        if "--wait" in rest and sys.stdin.isatty():
            _ask("\nPress enter to close")
        return code

    if action == "add":
        if not rest:
            print("xenia: name the credential", file=sys.stderr)
            return 2
        name = rest[0]
        hosts = _flag_values(rest, "--host")
        existing = broker.entry(conn, name)
        methods = _flag_values(rest, "--method") or None
        paths = _flag_values(rest, "--path") or None
        if existing is not None:
            hosts = hosts or json.loads(existing["hosts"])
        scope = _flag_values(rest, "--scope") or None
        verified = "--verified" in rest

        def save_policy() -> int | None:
            try:
                broker.register(
                    conn, name, hosts=hosts, methods=methods, paths=paths,
                    note=_flag_value(rest, "--note"),
                    service=_flag_value(rest, "--service"), scope=scope,
                    verified_at=(broker.stamp(broker.utcnow()) if verified
                                 else None),
                    expires_hint=_flag_value(rest, "--expires"))
            except ValueError as exc:
                print(f"xenia: {exc}", file=sys.stderr)
                return 2
            return None

        if "--policy-only" in rest:
            failed = save_policy()
            if failed:
                return failed
            print(f"Policy for '{name}' saved; the stored value is unchanged.")
            return 0

        try:
            value = read_value(name)
        except (ValueError, EOFError, KeyboardInterrupt) as exc:
            print(f"\nxenia: {exc or 'cancelled'} — nothing was changed.",
                  file=sys.stderr)
            return 1
        try:
            add(conn, name, value, hosts=hosts, methods=methods, paths=paths,
                note=_flag_value(rest, "--note"),
                service=_flag_value(rest, "--service"), scope=scope,
                verified_at=(broker.stamp(broker.utcnow()) if verified
                             else None),
                expires_hint=_flag_value(rest, "--expires"))
        except vault.VaultError as exc:
            print(f"xenia: {exc} — nothing was changed.", file=sys.stderr)
            return 1
        except ValueError as exc:
            print(f"xenia: {exc}", file=sys.stderr)
            return 2
        finally:
            del value

        print(f"Stored '{name}' in the {vault.configured_kind()}.")
        if hosts:
            print(f"Allowed at {', '.join(hosts)} once approved:\n"
                  f"  xenia grant {name} --host {hosts[0]}")
        else:
            print("You will be asked the first time something reaches for "
                  "it, and\nthat answer decides where it may be used.")
        return 0

    if action in ("rename", "mv"):
        named = [item for item in rest if not item.startswith("-")]
        if len(named) < 2:
            print("xenia: xenia secret rename OLD NEW", file=sys.stderr)
            return 2
        old, new = named[0], named[1]
        try:
            outcome = rename(conn, old, new)
        except (ValueError, vault.VaultError) as exc:
            print(f"xenia: {exc} — nothing was changed.", file=sys.stderr)
            return 2
        print(f"'{old}' is now '{new}'"
              + ("." if outcome["value"] else
                 " — there was no value in the store under the old name."))
        if outcome["store_error"]:
            print(f"xenia: the old value could not be deleted: "
                  f"{outcome['store_error']}", file=sys.stderr)
            return 1
        print(f"  Anything writing {{{{secret:{old}}}}} has to say "
              f"{{{{secret:{new}}}}} now.")
        return 0

    if action in ("rm", "remove", "forget"):
        named = [item for item in rest if not item.startswith("-")]
        if not named:
            return _remove_interactively(conn, broker, wait="--wait" in rest)
        return _remove(conn, named[0])

    if action == "sign":
        if len(rest) < 2:
            print("xenia: xenia secret sign NAME PROFILE key=value… "
                  "(or < profile.json)", file=sys.stderr)
            return 2
        name, profile = rest[0], rest[1]
        settings: dict[str, Any] = {}
        # `key=value` carries a flat profile; a nested one (a typed-signing
        # domain, its schema, its message bindings) has no flat spelling, and
        # a value stringified here reaches the scheme as a string and is
        # refused there. So the same stdin form as `secret body`.
        if len(rest) > 2:
            for item in rest[2:]:
                if "=" not in item:
                    continue
                key, value = item.split("=", 1)
                settings[key] = value
        else:
            raw = sys.stdin.read() if not sys.stdin.isatty() else ""
            if not raw.strip():
                print("xenia: give the profile as `key=value` arguments, or as "
                      "JSON on stdin — `xenia secret sign NAME PROFILE "
                      "< profile.json`", file=sys.stderr)
                return 2
            try:
                settings = json.loads(raw)
            except ValueError as exc:
                print(f"xenia: the profile on stdin is not JSON: {exc}",
                      file=sys.stderr)
                return 2
            if not isinstance(settings, dict):
                print("xenia: a signing profile must be a JSON object",
                      file=sys.stderr)
                return 2
        try:
            held = broker.set_profile(conn, name, profile, settings)
        except ValueError as exc:
            print(f"xenia: {exc}", file=sys.stderr)
            return 2
        from xenia import signing
        scheme = settings.get("scheme", "")
        ready = signing.available(scheme)
        print(f"'{name}' signing profile '{profile}' set to {scheme}.")
        print(f"  profiles: {', '.join(sorted(held))}")
        if not ready:
            print(f"  NOTE: the {scheme} scheme is not available on this "
                  f"machine — a call using it will refuse with 'unavailable' "
                  f"and say what to install.")
        return 0

    if action == "new":
        return wizard(rest)

    if action == "body":
        if not rest:
            print("xenia: xenia secret body NAME [--show] < policy.json",
                  file=sys.stderr)
            return 2
        name = rest[0]
        row = broker.entry(conn, name)
        if row is None:
            print(f"xenia: no credential called '{name}'", file=sys.stderr)
            return 2
        if "--show" in rest:
            held = broker.body_policy_of(row)
            if not held:
                print(f"'{name}' has no body policy: only its hosts, methods "
                      f"and paths are checked.")
                return 0
            print(json.dumps(held, indent=1))
            return 0

        raw = sys.stdin.read() if not sys.stdin.isatty() else ""
        if not raw.strip():
            print("xenia: give the policy as JSON on stdin — "
                  "`xenia secret body NAME < policy.json`", file=sys.stderr)
            return 2
        try:
            broker.set_body_policy(conn, name, json.loads(raw))
        except (ValueError, TypeError) as exc:
            print(f"xenia: {exc}", file=sys.stderr)
            return 2
        from xenia import policy as bodies
        print(f"'{name}' may now take these actions and no others:")
        for line in bodies.describe(broker.body_policy_of(
                broker.entry(conn, name))):
            print(f"  {line}")
        print("  anything else — including an endpoint added later — is "
              "refused.")
        return 0

    if action == "schemes":
        from xenia import signing
        print(f"{'SCHEME':22} AVAILABLE")
        for scheme in sorted(signing.SCHEMES):
            state = "yes" if signing.available(scheme) else "no — optional"
            print(f"{scheme:22} {state}")
        return 0

    if action == "test":
        outcome = vault.selftest()
        print(f"{outcome['backend']}: "
              f"{'ok' if outcome['ok'] else 'FAILED'} — {outcome['detail']}")
        return 0 if outcome["ok"] else 1

    print(f"xenia: unknown — `secret {action}`", file=sys.stderr)
    return _usage()


def _remove(conn, name: str) -> int:
    outcome = remove(conn, name)
    if outcome["store_error"]:
        print(f"xenia: removed the policy, but the store said: "
              f"{outcome['store_error']}", file=sys.stderr)
        return 1
    if not (outcome["policy"] or outcome["value"]):
        print(f"No credential '{name}'.")
        return 1
    print(f"Removed '{name}'."
          + ("" if outcome["policy"] else
             " (it had no policy here — a value left behind by a cancelled "
             "add)"))
    return 0


def _remove_interactively(conn, broker, *, wait: bool = False) -> int:
    """Pick one and remove it. What the tray's Delete… opens.

    `rm NAME` is still the whole command for anyone who knows the name; this
    is for the click that starts with no name at all.
    """
    if not sys.stdin.isatty():
        print("xenia: remove which credential? `xenia secret rm NAME`",
              file=sys.stderr)
        return 2

    rows = broker.registry(conn)
    known = {row["name"] for row in rows}
    names = [row["name"] for row in rows] + sorted(stored_names() - known)

    print("\nRemove a credential from xenia\n" + "-" * 30)
    if not names:
        print("\nNothing to remove — no credentials are registered.\n")
        if wait:
            _ask("Press enter to close")
        return 0

    where = {row["name"]: (", ".join(row["hosts"]) or "nothing yet")
             for row in rows}
    print()
    for index, name in enumerate(names, start=1):
        print(f"  {index:2}  {name:24} "
              f"{where.get(name, 'in the store, unknown to xenia')}")

    answer = _ask("\nRemove which one (number or name, blank to cancel)")
    if not answer:
        print("Nothing was changed.")
        if wait:
            _ask("\nPress enter to close")
        return 0

    if answer.isdigit() and 1 <= int(answer) <= len(names):
        name = names[int(answer) - 1]
    elif answer in names:
        name = answer
    else:
        print(f"xenia: no credential '{answer}' — nothing was changed.",
              file=sys.stderr)
        if wait:
            _ask("\nPress enter to close")
        return 2

    print(f"\n  Removing '{name}' deletes the value from the "
          f"{vault.configured_kind()} as well as the policy here, and the "
          f"value cannot be got back.")
    if not _ask_yes(f"  Remove '{name}'?", default=False):
        print("Nothing was changed.")
        if wait:
            _ask("\nPress enter to close")
        return 0

    code = _remove(conn, name)
    if wait:
        _ask("\nPress enter to close")
    return code


def _list(conn, broker) -> int:
    rows = broker.registry(conn)
    stored = stored_names()
    known = {row["name"] for row in rows}

    if not rows and not stored:
        print("No credentials yet. Add one with `xenia secret new`.")
        return 0

    live = {}
    for row in broker.grants(conn):
        live.setdefault(row["name"], []).append(row)

    print(f"{'NAME':20} {'ALLOWED AT':26} {'METHODS':16} {'SIGNS':12} "
          f"LAST USED")
    for row in rows:
        if not row["hosts"]:
            row = {**row, "hosts": ["nothing yet — asked on first use"]}
        approved = live.get(row["name"], [])
        mark = f"  ({len(approved)} live grant"  \
               f"{'' if len(approved) == 1 else 's'})" if approved else ""
        print(f"{row['name']:20} {','.join(row['hosts'])[:26]:26} "
              f"{','.join(row['methods'])[:16]:16} "
              f"{','.join(row['schemes'])[:12]:12} "
              f"{(row['last_used_at'] or 'never')[:19]}{mark}")
        for line in row.get("actions") or []:
            print(f"  {'':18} may: {line}")
        if row["name"] not in stored and stored:
            print(f"  {'':18} NOT IN THE STORE — the value is gone; "
                  f"`xenia secret new` to put it back")
        if row.get("service"):
            state = ("scope NEVER VERIFIED"
                     if row["scope_stale"] else
                     f"scope verified {row['scope_verified_at'][:10]}")
            print(f"  {'':18} {row['service']}: "
                  f"{', '.join(row['scope'] or ['no scope recorded'])} — "
                  f"{state}")

    for orphan in sorted(stored - known):
        print(f"{orphan:20} {'in the store, unknown to xenia':26} "
              f"{'':16} {'':12} —")
        print(f"  {'':18} left behind by a cancelled add; "
              f"`xenia secret rm {orphan}` clears it")
    return 0


def _grant(conn, broker, argv: list[str]) -> int:
    if not argv:
        print("xenia: grant which credential?", file=sys.stderr)
        return 2
    name = argv[0]
    host = _flag_value(argv, "--host")
    if not host:
        entry = broker.entry(conn, name)
        hosts = json.loads(entry["hosts"]) if entry else []
        if len(hosts) == 1 and "*" not in hosts[0]:
            host = hosts[0]
        else:
            print("xenia: --host is required", file=sys.stderr)
            return 2

    mutating = "--write" in argv
    window = _flag_value(argv, "--for")
    try:
        seconds = duration(window) if window else None
        row = broker.grant(conn, name, host, mutating=mutating,
                           seconds=seconds, source="cli")
    except ValueError as exc:
        print(f"xenia: {exc}", file=sys.stderr)
        return 2

    print(f"Approved '{name}' for {host}"
          f"{' including writes' if mutating else ' (reads only)'}.")
    print(f"  until   {row['expires_at'][:19]}  (slides forward on use)")
    print(f"  ceiling {row['ceiling_at'][:19]}  (does not move)")
    return 0


def _grants(conn, broker, everything: bool) -> int:
    rows = broker.grants(conn, live_only=not everything)
    if not rows:
        print("No live grants." if not everything else "No grants recorded.")
        return 0
    print(f"{'NAME':22} {'HOST':28} {'WRITES':7} {'UNTIL':20} USES")
    for row in rows:
        print(f"{row['name']:22} {row['host'][:28]:28} "
              f"{'yes' if row['mutating'] else 'no':7} "
              f"{row['expires_at'][:19]:20} {row['uses']}")
    return 0


def _usage() -> int:
    print("""xenia credentials — values live in the OS store, never in xenia

  xenia secrets setup [--install gnome-keyring|keepassxc] [--wire]
                                  find a credential store, prove it works,
                                  install and wire one up if there is none

  xenia secret add NAME [--host H] [--method GET] [--path /api/*]
                        [--note TEXT] [--policy-only]
                        [--service NAME] [--scope read-only] [--verified]
                        [--expires DATE]
                                  register a credential and store its value.
                                  The value is typed, or piped in — never
                                  passed as an argument. --host is optional:
                                  with none, the first use raises a prompt and
                                  the answer sets the scope
  xenia secret sign NAME PROFILE scheme=hmac template='{ts}{method}{path}{body}'
                        digest=sha256 encoding=base64
  xenia secret sign NAME PROFILE < profile.json
                                  how this credential signs. The scheme AND the
                                  string it signs are config, not something a
                                  caller may choose — a caller who picks what
                                  gets signed has a signing oracle. Give it as
                                  JSON when the profile nests: a typed-signing
                                  domain, schema and message bindings have no
                                  `key=value` spelling
  xenia secret body NAME [--show] < policy.json
                                  the actions this credential may take, over
                                  the parsed request. Required for a
                                  --service credential, where a route alone
                                  cannot separate a harmless call from a
                                  damaging one
  xenia secret schemes            which signing schemes work on this machine
  xenia secret new                add and scope one, interactively — the same
                                  thing the tray's Credentials → Add… opens
  xenia secret list               what is registered, and what is approved.
                                  The report's Credentials tab is the same
                                  list, and is where one is added, renamed or
                                  removed with the mouse
  xenia secret rename OLD NEW     give one a different name, keeping its
                                  policy, its approvals and its history.
                                  Anything writing {{secret:OLD}} has to say
                                  {{secret:NEW}} afterwards
  xenia secret rm [NAME]          forget the policy and delete the value.
                                  With no name it lists what is there and
                                  asks which — the same thing the tray's
                                  Credentials → Delete… opens
  xenia secret test               store, read back and delete a test value

  xenia grant NAME --host H [--write] [--for 4h]
                                  approve use up front. Usually unnecessary:
                                  the first use raises a prompt and answering
                                  it does the same thing. Reads get 4h, writes
                                  30m, and no approval outlives a 4h ceiling
  xenia grants [--all]            what is approved right now
  xenia revoke NAME [--host H]    end it early
""")
    return 0
