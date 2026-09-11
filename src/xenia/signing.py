"""Signing: authenticating a request without the credential being in it.

Some APIs do not take a credential in the request at all — they take a
signature computed over it. A signature is not the credential: it is specific
to one request and worth nothing against another, so it can be returned to the
caller when the credential never can.

Both the scheme and the string it signs live on the credential row, not in the
caller's request. A caller that could choose what gets signed could have
arbitrary bytes signed with the key and reuse them elsewhere; it also means a
format guessed wrong costs a config change rather than a code change.

A scheme is a callable in SCHEMES taking a Context and returning the string to
place. `available()` says whether it can run here.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import quote, urlsplit


class SchemeError(Exception):
    """A scheme cannot sign this. Carries the reason, and a refusal code."""

    def __init__(self, message: str, code: str = "off-policy") -> None:
        super().__init__(message)
        self.code = code


@dataclass
class Context:
    """Everything a scheme may sign, read off the request being sent.

    A scheme reads from here and nowhere else, so a template cannot cover
    anything but this request.
    """

    secret: str
    method: str
    url: str
    headers: dict[str, str]
    body: str
    config: dict[str, Any]
    nonce: int
    now: float
    extras: dict[str, str] = field(default_factory=dict)

    # -- the pieces a template may name ------------------------------------

    @property
    def parts(self):
        return urlsplit(self.url)

    def variables(self) -> dict[str, str]:
        parts = self.parts
        query = f"?{parts.query}" if parts.query else ""
        return {
            "method": self.method.upper(),
            "path": parts.path or "/",
            "query": parts.query,
            "path_query": (parts.path or "/") + query,
            "host": parts.hostname or "",
            "body": self.body,
            "body_sha256_hex": hashlib.sha256(self.body.encode()).hexdigest(),
            "nonce": str(self.nonce),
            "ts": str(int(self.now)),
            "ts_ms": str(int(self.now * 1000)),
            "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%S",
                                    time.gmtime(self.now)) +
                      f".{int(self.now * 1000) % 1000:03d}Z",
            "amz_date": time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(self.now)),
            "amz_day": time.strftime("%Y%m%d", time.gmtime(self.now)),
            **self.extras,
        }


def render(template: str, variables: dict[str, str]) -> str:
    """Fill a template, refusing a name it does not know.

    An unknown `{field}` would otherwise be signed as literal text and
    rejected by the far side with nothing to say why.
    """
    out: list[str] = []
    rest = template
    while rest:
        head, sep, tail = rest.partition("{")
        out.append(head)
        if not sep:
            break
        name, closed, rest = tail.partition("}")
        if not closed:
            raise SchemeError(f"unclosed '{{' in the signing template")
        if name not in variables:
            raise SchemeError(
                f"the signing template names {{{name}}}, which is not one of: "
                f"{', '.join(sorted(variables))}")
        out.append(variables[name])
    return "".join(out)


def _digest(name: str):
    try:
        return getattr(hashlib, name)
    except AttributeError as exc:
        raise SchemeError(f"no such digest: {name}") from exc


def _encode(raw: bytes, encoding: str) -> str:
    if encoding == "hex":
        return raw.hex()
    if encoding == "base64":
        return base64.b64encode(raw).decode()
    raise SchemeError(f"no such signature encoding: {encoding} (hex, base64)")


# --------------------------------------------------------------------------
# HMAC — anything with a shared secret
# --------------------------------------------------------------------------

def hmac_scheme(ctx: Context) -> str:
    """HMAC of a templated string, in hex or base64.

    Config: `template` (required), `digest` (sha256), `encoding` (base64).
    """
    template = ctx.config.get("template")
    if not template:
        raise SchemeError(
            "this credential's signing profile has no 'template' — the string "
            "to sign is config, not something the caller may choose")
    message = render(template, ctx.variables())
    raw = hmac.new(ctx.secret.encode(),
                   message.encode(),
                   _digest(ctx.config.get("digest", "sha256"))).digest()
    return _encode(raw, ctx.config.get("encoding", "base64"))


# --------------------------------------------------------------------------
# AWS SigV4 — its own canonical form, so no template
# --------------------------------------------------------------------------

SIGV4_ALGORITHM = "AWS4-HMAC-SHA256"


def sigv4_scheme(ctx: Context) -> str:
    """The whole `Authorization` header value for AWS Signature Version 4.

    Config: `region`, `service`, and `key_id` (an identifier rather than a
    secret; `key_id_from` names another credential when a site would rather
    keep it in the store). The whole header, because the signature is
    meaningless without the scope and signed-header list beside it.
    """
    region = ctx.config.get("region")
    service = ctx.config.get("service")
    key_id = ctx.extras.get("key_id") or ctx.config.get("key_id")
    if not (region and service and key_id):
        raise SchemeError(
            "an aws-sigv4 profile needs 'region', 'service' and a 'key_id' "
            "(or 'key_id_from' naming another credential)")

    parts = ctx.parts
    payload_hash = hashlib.sha256(ctx.body.encode()).hexdigest()
    amz_date = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(ctx.now))
    day = amz_date[:8]

    headers = {k.lower(): " ".join(str(v).split())
               for k, v in ctx.headers.items()}
    headers["host"] = parts.netloc
    headers["x-amz-date"] = amz_date
    # S3 signs the payload hash as a header; elsewhere adding it changes
    # SignedHeaders and invalidates the signature.
    if service == "s3":
        headers.setdefault("x-amz-content-sha256", payload_hash)
    signed = sorted(headers)
    canonical_headers = "".join(f"{k}:{headers[k]}\n" for k in signed)
    signed_headers = ";".join(signed)

    canonical_query = "&".join(sorted(
        f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}"
        for k, v in (
            (pair.split("=", 1) + [""])[:2]
            for pair in parts.query.split("&") if pair)))

    canonical_request = "\n".join([
        ctx.method.upper(),
        quote(parts.path or "/", safe="/-_.~"),
        canonical_query,
        canonical_headers,
        signed_headers,
        payload_hash,
    ])

    scope = f"{day}/{region}/{service}/aws4_request"
    to_sign = "\n".join([
        SIGV4_ALGORITHM, amz_date, scope,
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    ])

    key = f"AWS4{ctx.secret}".encode()
    for step in (day, region, service, "aws4_request"):
        key = hmac.new(key, step.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()

    # The headers the signature covers must reach the wire, or the far side
    # canonicalises something different and rejects it.
    ctx.headers["x-amz-date"] = amz_date
    if service == "s3":
        ctx.headers.setdefault("x-amz-content-sha256", payload_hash)
    return (f"{SIGV4_ALGORITHM} Credential={key_id}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}")


# --------------------------------------------------------------------------
# Elliptic curves — optional, and absent rather than approximated
# --------------------------------------------------------------------------

def _optional(module: str, install: str) -> Callable:
    """A scheme that is real when its library is installed, and honest when not.

    Xenia carries no cryptographic implementation of its own. A pure-Python
    scalar multiplication leaks the private key through timing, and the
    signature it produces verifies exactly as well as a sound one — so the
    failure would be invisible. These bind to a reviewed implementation, are
    optional, and say so by name when it is missing.
    """

    def scheme(ctx: Context) -> str:
        raise SchemeError(
            f"the '{ctx.config.get('scheme')}' signing scheme needs {module}, "
            f"which is not installed here ({install}). It is optional on "
            f"purpose: xenia binds to a reviewed implementation rather than "
            f"carrying its own.",
            code="unavailable")

    def available() -> bool:
        try:
            __import__(module)
            return True
        except ImportError:
            return False

    scheme.available = available          # type: ignore[attr-defined]
    scheme.needs = module                 # type: ignore[attr-defined]
    return scheme


def eip712_scheme(ctx: Context) -> str:
    """Sign a profile-bound EIP-712 message with a reviewed account library.

    The profile fixes the domain, schema, input policy and message bindings.
    Hash fields are derived here from the input the policy checks. Accepting
    a caller-supplied hash would hide the request from that policy.
    """
    try:
        from eth_account import Account
        from eth_account.messages import encode_typed_data
        from eth_keys.backends import CoinCurveECCBackend
        import coincurve  # noqa: F401 -- never fall back to Python scalar multiplication
    except ImportError as exc:
        raise SchemeError(
            "the 'secp256k1-eip712' signing scheme needs eth-account and coincurve "
            "(pip install 'xenia[eip712]'). It is optional "
            "on purpose: xenia binds to a reviewed implementation.",
            code="unavailable") from exc

    primary = ctx.config.get("primary_type")
    domain = ctx.config.get("domain")
    types = ctx.config.get("types")
    if not isinstance(primary, str) or not primary:
        raise SchemeError("an eip712 profile needs a non-empty 'primary_type'")
    if not isinstance(domain, dict) or not isinstance(types, dict):
        raise SchemeError("an eip712 profile needs 'domain' and 'types' objects")
    try:
        message = json.loads(ctx.body)
    except (TypeError, ValueError) as exc:
        raise SchemeError("an eip712 message must be a JSON object") from exc
    if not isinstance(message, dict):
        raise SchemeError("an eip712 message must be a JSON object")
    from . import policy
    try:
        policy.check(ctx.config.get("payload_policy") or {}, "SIGN", "/",
                     {"Content-Type": "application/json"}, ctx.body)
    except (policy.Denied, policy.Unparsed) as exc:
        raise SchemeError(f"typed-signing input refused: {exc}") from exc
    bindings = ctx.config.get("message")
    if bindings is not None:
        if not isinstance(bindings, dict):
            raise SchemeError("typed-signing message bindings must be an object")
        message = {key: _binding(spec, message, ctx)
                   for key, spec in bindings.items()}
    full_message = {"types": types, "domain": domain,
                    "primaryType": primary, "message": message}
    try:
        account = Account()
        account.set_key_backend(CoinCurveECCBackend())
        signed = account.sign_message(encode_typed_data(full_message=full_message),
                                      private_key=ctx.secret)
    except (TypeError, ValueError, KeyError) as exc:
        # Parser errors can contain the value they were parsing, including a key.
        raise SchemeError("invalid typed message, profile or signing key") from exc
    return "0x" + signed.signature.hex()


def _eip712_available() -> bool:
    try:
        import eth_account  # noqa: F401
        import coincurve  # noqa: F401
        import msgpack  # noqa: F401
        return True
    except ImportError:
        return False


eip712_scheme.available = _eip712_available  # type: ignore[attr-defined]
eip712_scheme.needs = "eth-account, coincurve, msgpack"  # type: ignore[attr-defined]


def _binding(spec: dict, payload: dict, ctx: Context, depth: int = 0) -> Any:
    """A small declarative byte recipe, held in the profile, never caller code.

    Input paths, literals, nonce, MessagePack, fixed-width integers and Keccak
    cover typed messages that commit to structured actions. No evaluation,
    imports, venue knowledge or network calls come from configuration.
    """
    if depth > 8 or not isinstance(spec, dict) or len(spec) != 1:
        raise SchemeError("invalid typed-signing message binding")
    kind, value = next(iter(spec.items()))
    try:
        if kind == "literal":
            return value
        if kind == "field":
            from .policy import _at
            found = _at(payload, value)
            if found is None:
                raise SchemeError("typed-signing input field is absent")
            return found
        if kind == "nonce" and value is True:
            return ctx.nonce
        if kind == "hex":
            return bytes.fromhex(value)
        if kind == "msgpack":
            import msgpack
            return msgpack.packb(_binding(value, payload, ctx, depth + 1))
        if kind == "uint64":
            number = _binding(value, payload, ctx, depth + 1)
            if type(number) is not int or not 0 <= number < 2**64:
                raise SchemeError("typed-signing uint64 is out of range")
            return number.to_bytes(8, "big")
        if kind == "keccak" and isinstance(value, list) and 0 < len(value) <= 16:
            from eth_utils import keccak
            parts = [_binding(part, payload, ctx, depth + 1) for part in value]
            if any(not isinstance(part, bytes) for part in parts):
                raise SchemeError("typed-signing hash inputs must be bytes")
            return keccak(b"".join(parts))
    except ImportError as exc:
        raise SchemeError("typed-signing dependency is unavailable", code="unavailable") from exc
    except (ValueError, TypeError, OverflowError) as exc:
        raise SchemeError("invalid typed-signing message binding") from exc
    raise SchemeError("unknown typed-signing message binding")


stark_scheme = _optional("crypto_cpp_py", "pip install crypto-cpp-py")


SCHEMES: dict[str, Callable[[Context], str]] = {
    "hmac": hmac_scheme,
    "aws-sigv4": sigv4_scheme,
    "secp256k1-eip712": eip712_scheme,
    "stark": stark_scheme,
}


def available(name: str) -> bool:
    scheme = SCHEMES.get(name)
    if scheme is None:
        return False
    check = getattr(scheme, "available", None)
    return check() if check else True


def sign(profile: dict[str, Any], ctx: Context) -> str:
    name = profile.get("scheme")
    scheme = SCHEMES.get(name or "")
    if scheme is None:
        raise SchemeError(
            f"no signing scheme called {name!r} — xenia has: "
            f"{', '.join(sorted(SCHEMES))}")
    ctx.config = profile
    return scheme(ctx)
