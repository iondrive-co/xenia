"""Policy over the request itself, not just over where it goes.

Hosts, methods and paths cannot always separate a harmless call from a
damaging one: the two often share all three, and differ only in a field. So a
credential may carry an allowlist of actions — a method, a path, and what that
request is allowed to contain. Anything matching no action is refused, which
means an endpoint nobody has heard of yet is refused too.

Deliberately absent: any derived value (a field that is not in the request
cannot be checked), any network call (a check that fetches something fails
open when it times out), and any normalising of values (a normaliser that maps
one wrong is an allowlist that permits the wrong thing while reading as
protection).
"""

from __future__ import annotations

import json
from decimal import Decimal, InvalidOperation
from typing import Any
from urllib.parse import parse_qsl, urlsplit

JSON_TYPES = ("application/json", "text/json", "application/json-rpc")
FORM_TYPES = ("application/x-www-form-urlencoded",)


class Unparsed(Exception):
    """The request could not be read, so it cannot be permitted.

    A body xenia cannot parse is one whose fields it cannot check.
    """


class Denied(Exception):
    """The request parsed, and the policy does not permit it."""


def content_type(headers: dict) -> str:
    for key, value in (headers or {}).items():
        if str(key).lower() == "content-type":
            return str(value).split(";")[0].strip().lower()
    return ""


def fields(method: str, url: str, headers: dict, body: str | None
           ) -> list[dict[str, Any]]:
    """Every field the far side will read, from wherever this API puts them.

    Some send JSON; others put the same parameters in the query string or a
    form-encoded body. Reading only JSON would leave those unchecked while
    reporting that policy was in force. A list, because a request may carry an
    array of items: each is checked and all must pass.
    """
    query = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
    kind = content_type(headers)
    text = (body or "").strip()

    if not text:
        return [query]

    if kind in FORM_TYPES or (not kind and "=" in text and "{" not in text):
        parsed: Any = dict(parse_qsl(text, keep_blank_values=True))
    elif kind in JSON_TYPES or (not kind and text[:1] in "{["):
        try:
            parsed = json.loads(text)
        except ValueError as exc:
            raise Unparsed(f"the body is not the JSON it is labelled as: {exc}")
    else:
        raise Unparsed(
            f"xenia cannot read a {kind or 'unlabelled'} body, so it cannot "
            f"check what is in it")

    rows = parsed if isinstance(parsed, list) else [parsed]
    out: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            raise Unparsed("a request body must be an object, or an array of "
                           "them")
        clash = [key for key in query
                 if key in row and str(query[key]) != str(row[key])]
        if clash:
            raise Unparsed(
                f"{', '.join(sorted(clash))} appears in both the query string "
                f"and the body with different values, and which one the far "
                f"side reads is not xenia's to guess")
        out.append({**query, **row})
    return out


def _at(row: dict, path: str) -> Any:
    """One field, by name or by dotted path. Missing is None."""
    value: Any = row
    for step in path.split("."):
        if isinstance(value, list) and step.isdecimal():
            index = int(step)
            value = value[index] if index < len(value) else None
        elif isinstance(value, dict) and step in value:
            value = value[step]
        else:
            return None
    return value


def _same(value: Any, wanted: Any) -> bool:
    """Equality as the far side would read it off the wire.

    A form-encoded `true` is the string and a JSON one is the boolean. Telling
    them apart would let a policy written for one encoding pass everything in
    the other.
    """
    if isinstance(wanted, bool) or isinstance(value, bool):
        return _truth(value) == _truth(wanted)
    return str(value) == str(wanted)


def _truth(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("true", "1", "yes"):
        return True
    if text in ("false", "0", "no"):
        return False
    return None


def _decimal(value: Any) -> Decimal:
    try:
        number = Decimal(str(value))
        if not number.is_finite():
            raise ValueError("non-finite number")
        return number
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise Denied(f"{value!r} is not a number, and a cap applies to it"
                     ) from exc


def _matches_route(action: dict, method: str, path: str) -> bool:
    import fnmatch

    methods = [m.upper() for m in action.get("methods", [])]
    if methods and method.upper() not in methods:
        return False
    paths = action.get("paths") or []
    return any(fnmatch.fnmatch(path, pattern) for pattern in paths)


def check(policy: dict, method: str, url: str, headers: dict,
          body: str | None) -> str:
    """Permit this request under one named action, or raise.

    Returns the action's name, so the record can say which rule let it through.
    """
    actions = (policy or {}).get("actions") or {}
    if not actions:
        raise Denied("this credential has a body policy with no actions in "
                     "it, which permits nothing")

    path = urlsplit(url).path or "/"
    candidates = {name: action for name, action in actions.items()
                  if _matches_route(action, method, path)}
    if not candidates:
        raise Denied(
            f"no action permits {method} {path}. This credential allows: "
            + "; ".join(f"{name} ({'/'.join(action.get('paths') or [])})"
                        for name, action in sorted(actions.items()))
            + ". Anything not on that list is refused whether or not anyone "
              "thought of it.")

    rows = fields(method, url, headers, body)
    if not rows:
        rows = [{}]

    failures: list[str] = []
    for name, action in sorted(candidates.items()):
        why = _permits(action, rows)
        if why is None:
            return name
        failures.append(f"{name}: {why}")
    raise Denied("; ".join(failures))


def _permits(action: dict, rows: list[dict]) -> str | None:
    """None when every row passes, else why the first failing one did not."""
    for row in rows:
        for field, names in (action.get("only") or {}).items():
            value = row if field == "" else _at(row, field)
            if not isinstance(value, dict) or set(value) != set(names):
                return f"{field or 'body'} must contain exactly the configured fields"

        for field, count in (action.get("length") or {}).items():
            value = _at(row, field)
            if not isinstance(value, list) or len(value) != count:
                return f"{field} must be an array of {count} items"

        for field in action.get("required", []):
            if _at(row, field) is None:
                return f"{field} is required and absent"

        for field in action.get("forbidden", []):
            if _at(row, field) is not None:
                return f"{field} is not allowed on this action"

        for field, wanted in (action.get("equals") or {}).items():
            value = _at(row, field)
            if value is None:
                return f"{field} must be {wanted!r} and is absent"
            if not _same(value, wanted):
                return f"{field} must be {wanted!r}, not {value!r}"

        for field, allowed in (action.get("in") or {}).items():
            value = _at(row, field)
            if value is None:
                return f"{field} must be one of {allowed} and is absent"
            if not any(_same(value, option) for option in allowed):
                return f"{field} is {value!r}, which is not one of {allowed}"

        for field, ceiling in (action.get("max") or {}).items():
            value = _at(row, field)
            if value is None:
                return (f"{field} is capped at {ceiling} and is absent — a "
                        f"cap cannot be applied to a field that is not there")
            if _decimal(value) > _decimal(ceiling):
                return f"{field} is {value}, over the cap of {ceiling}"

        for field, floor in (action.get("min") or {}).items():
            value = _at(row, field)
            if value is None:
                return f"{field} has a minimum of {floor} and is absent"
            if _decimal(value) < _decimal(floor):
                return f"{field} is {value}, under the minimum of {floor}"
    return None


def describe(policy: dict) -> list[str]:
    """The policy in words, for `xenia secret list` and the report page."""
    out = []
    for name, action in sorted(((policy or {}).get("actions") or {}).items()):
        bits = [f"{'/'.join(action.get('methods') or ['*'])} "
                f"{','.join(action.get('paths') or ['*'])}"]
        for field, allowed in (action.get("in") or {}).items():
            bits.append(f"{field} in {','.join(str(a) for a in allowed)}")
        for field, wanted in (action.get("equals") or {}).items():
            bits.append(f"{field}={wanted}")
        for field, ceiling in (action.get("max") or {}).items():
            bits.append(f"{field}<={ceiling}")
        out.append(f"{name}: " + "; ".join(bits))
    return out
