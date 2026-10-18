"""Signing: authenticating a request without the credential being in it.

Some APIs do not take a credential in the request at all — they take a
signature computed over it. A signature is not the credential: it is specific
to one request and worth nothing against another, so it can be returned to the
caller when the credential never can.

Both the scheme and the string it signs live on the credential row, not in the
caller's request. A caller that could choose what gets signed could have
arbitrary bytes signed with the key and reuse them elsewhere; it also means a
format guessed wrong costs a config change rather than a code change.

"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable
from urllib.parse import parse_qsl, quote, urlsplit

from . import providers


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

    def form_fields(self) -> dict[str, str]:
        if not self.body or self.body.lstrip()[:1] in ("{", "["):
            return {}
        return {f"form.{k}": v for k, v in parse_qsl(self.body, keep_blank_values=True)}

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
            **self.form_fields(),
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
            known = sorted(k for k in variables if not k.startswith("form."))
            raise SchemeError(
                f"the signing template names {{{name}}}, which this request "
                f"does not have; it may use {', '.join(known)}, or "
                f"form.<field> for a field of a form body")
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

    Config: `template` (required), `digest` (sha256), `encoding` (base64),
    `key_encoding` (utf8), `timestamp_header` (none).

    `key_encoding` is how the STORED credential turns into HMAC key bytes.

    `timestamp_header` names a header that must carry the same instant the
    signature covers. A scheme whose message includes `{ts}` or `{ts_ms}` and
    whose far side re-derives it from a header has to send the value it
    signed, not one the caller guessed a moment earlier; SigV4 does the same
    with `x-amz-date`.
    """
    template = ctx.config.get("template")
    if not template:
        raise SchemeError(
            "this credential's signing profile has no 'template' — the string "
            "to sign is config, not something the caller may choose")
    variables = ctx.variables()
    message = render(template, variables)
    data = message.encode()
    prehash = ctx.config.get("prehash_template")
    if prehash:
        data += _digest(ctx.config.get("prehash_digest", "sha256"))(
            render(prehash, variables).encode()).digest()
    raw = hmac.new(_key_bytes(ctx.secret, ctx.config.get("key_encoding", "utf8")),
                   data,
                   _digest(ctx.config.get("digest", "sha256"))).digest()

    # THE PUBLIC HALF OF A KEY PAIR. Most REST services send an identifier
    # beside the signature
    api_header = ctx.config.get("api_key_header")
    if api_header:
        key_id = ctx.extras.get("key_id") or ctx.config.get("key_id")
        if not key_id:
            raise SchemeError(
                "this profile names an 'api_key_header' but no 'key_id' to put "
                "in it (or 'key_id_from' naming another credential)")
        ctx.headers[api_header] = str(key_id)

    header = ctx.config.get("timestamp_header")
    if header:
        name = str(ctx.config.get("timestamp_variable", "ts_ms"))
        if name not in variables:
            raise SchemeError(
                f"timestamp_variable {name!r} is not one of: "
                f"{', '.join(sorted(variables))}")
        ctx.headers[header] = variables[name]

    return _encode(raw, ctx.config.get("encoding", "base64"))


def _key_bytes(secret: str, encoding: str) -> bytes:
    """The stored credential as HMAC key material."""
    if encoding in ("utf8", "utf-8", "text", "raw"):
        return secret.encode()
    if encoding == "base64":
        try:
            return base64.b64decode(secret, validate=True)
        except Exception as exc:
            raise SchemeError(
                "this profile says the credential is base64, and it does not "
                "decode — check which half of the service's key pair is stored",
                code="off-policy") from exc
    if encoding == "hex":
        try:
            return bytes.fromhex(secret)
        except ValueError as exc:
            raise SchemeError(
                "this profile says the credential is hex, and it does not "
                "decode", code="off-policy") from exc
    raise SchemeError(
        f"no such key encoding: {encoding} (utf8, base64, hex)")


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


SCHEMES: dict[str, Callable[[Context], str]] = {
    "hmac": hmac_scheme,
    "aws-sigv4": sigv4_scheme,
}


def schemes() -> set[str]:
    return set(SCHEMES) | set(providers.configured())


def available(name: str) -> bool:
    scheme = SCHEMES.get(name)
    if scheme is None:
        return providers.available(name)
    check = getattr(scheme, "available", None)
    return check() if check else True


def sign(profile: dict[str, Any], ctx: Context) -> str:
    name = profile.get("scheme")
    if not isinstance(name, str):
        raise SchemeError("a signing profile needs a scheme name")
    scheme = SCHEMES.get(name or "")
    ctx.config = profile
    if scheme is not None:
        return scheme(ctx)
    if name not in providers.configured():
        raise SchemeError(
            f"no signing scheme called {name!r} — xenia has: "
            f"{', '.join(sorted(schemes()))}")
    try:
        signature, headers = providers.invoke(name, asdict(ctx))
    except providers.ProviderError as exc:
        raise SchemeError(str(exc), code=exc.code) from exc
    ctx.headers.update(headers)
    return signature
