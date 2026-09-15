from __future__ import annotations

import calendar
import hashlib
import hmac
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from xenia import signing

# 2015-08-30T12:36:00Z — the moment the published AWS test suite signs at.
AWS_WHEN = calendar.timegm(time.strptime("20150830T123600Z", "%Y%m%dT%H%M%SZ"))
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
AWS_PROFILE = {"scheme": "aws-sigv4", "region": "us-east-1",
               "service": "service", "key_id": "AKIDEXAMPLE"}


def context(**kwargs) -> signing.Context:
    base = dict(secret="s3cret", method="GET",
                url="https://example.test/api/v4/thing", headers={}, body="",
                config={}, nonce=1, now=1_600_000_000.0)
    base.update(kwargs)
    return signing.Context(**base)


# -- AWS SigV4, against the published vectors -------------------------------

@pytest.mark.parametrize("name,url,method,signature", [
    ("get-vanilla", "https://example.amazonaws.com/", "GET",
     "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"),
    ("get-vanilla-query-order-key-case",
     "https://example.amazonaws.com/?Param2=value2&Param1=value1", "GET",
     "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"),
    ("post-vanilla", "https://example.amazonaws.com/", "POST",
     "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b"),
])
def test_sigv4_reproduces_the_published_test_suite(name, url, method,
                                                   signature):
    """Byte-for-byte against AWS's own vectors.

    A signing implementation that is nearly right is rejected by the far side
    with no explanation, so the only useful test is one someone else computed
    the answer to.
    """
    header = signing.sign(AWS_PROFILE, context(
        secret=AWS_SECRET, method=method, url=url, headers={}, body="",
        now=AWS_WHEN))

    assert f"Signature={signature}" in header
    assert "Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request" \
        in header


def test_sigv4_signs_the_body_it_is_given():
    plain = signing.sign(AWS_PROFILE, context(secret=AWS_SECRET, now=AWS_WHEN,
                                              url="https://x.test/"))
    with_body = signing.sign(AWS_PROFILE, context(
        secret=AWS_SECRET, now=AWS_WHEN, url="https://x.test/", body='{"a":1}'))

    assert plain != with_body


def test_sigv4_puts_the_headers_it_signed_where_they_will_be_sent():
    ctx = context(secret=AWS_SECRET, now=AWS_WHEN, url="https://x.test/")
    signing.sign(AWS_PROFILE, ctx)

    assert ctx.headers["x-amz-date"] == "20150830T123600Z"


def test_s3_gets_the_payload_hash_header_and_other_services_do_not():
    """It is signed where it is required and absent where it is not.

    Adding it everywhere changes SignedHeaders and invalidates the signature
    against every service that does not want it.
    """
    s3 = context(secret=AWS_SECRET, now=AWS_WHEN, url="https://b.s3.test/k")
    signing.sign({**AWS_PROFILE, "service": "s3"}, s3)
    other = context(secret=AWS_SECRET, now=AWS_WHEN, url="https://x.test/")
    signing.sign(AWS_PROFILE, other)

    assert "x-amz-content-sha256" in s3.headers
    assert "x-amz-content-sha256" not in other.headers


def test_sigv4_says_what_a_profile_is_missing():
    with pytest.raises(signing.SchemeError, match="region"):
        signing.sign({"scheme": "aws-sigv4"}, context())


# -- HMAC -------------------------------------------------------------------

def test_hmac_signs_the_template_the_row_carries():
    profile = {"scheme": "hmac", "template": "{ts}{method}{path}{body}",
               "digest": "sha256", "encoding": "base64"}
    ctx = context(body='{"n":1}', method="POST")

    got = signing.sign(profile, ctx)

    expected = hmac.new(
        b"s3cret", f"1600000000POST/api/v4/thing{{\"n\":1}}".encode(),
        hashlib.sha256).digest()
    import base64
    assert got == base64.b64encode(expected).decode()


def test_hmac_encodings_and_digests_are_config():
    template = {"scheme": "hmac", "template": "{path}"}
    hex_sha512 = signing.sign(
        {**template, "digest": "sha512", "encoding": "hex"}, context())

    assert len(hex_sha512) == 128
    assert int(hex_sha512, 16) >= 0


def test_a_profile_with_no_template_refuses_rather_than_signing_nothing():
    with pytest.raises(signing.SchemeError, match="template"):
        signing.sign({"scheme": "hmac"}, context())


def test_a_template_naming_something_unknown_is_a_refusal_not_a_literal():
    """A typo would otherwise sign the literal text `{tstamp}` and be
    rejected by the far side with nothing to say why."""
    with pytest.raises(signing.SchemeError, match="tstamp"):
        signing.sign({"scheme": "hmac", "template": "{tstamp}{path}"},
                     context())


def test_the_nonce_and_the_clock_are_available_to_a_template():
    profile = {"scheme": "hmac", "template": "{nonce}", "encoding": "hex"}
    one = signing.sign(profile, context(nonce=1))
    two = signing.sign(profile, context(nonce=2))

    assert one != two


def test_variables_are_read_off_the_request_and_not_from_the_caller():
    variables = context(url="https://h.test/p?a=1", method="post").variables()

    assert variables["method"] == "POST"
    assert variables["path"] == "/p"
    assert variables["query"] == "a=1"
    assert variables["host"] == "h.test"


# -- the curves -------------------------------------------------------------

@pytest.mark.parametrize("scheme", ["secp256k1-eip712", "stark"])
def test_a_curve_scheme_is_absent_by_name_rather_than_approximated(scheme):
    """A pure-Python scalar multiply leaks the key through timing, and the
    signature it produces verifies exactly as well as a sound one, so xenia
    binds to a reviewed implementation rather than carrying its own."""
    if signing.available(scheme):
        pytest.skip(f"{scheme} has its optional dependency installed here")

    with pytest.raises(signing.SchemeError) as raised:
        signing.sign({"scheme": scheme}, context())

    assert raised.value.code == "unavailable"
    assert "pip install" in str(raised.value)


def test_every_scheme_reports_whether_it_can_run_here():
    reported = {name: signing.available(name) for name in signing.SCHEMES}

    assert reported["hmac"] is True
    assert reported["aws-sigv4"] is True
    assert set(reported) == set(signing.SCHEMES)


def test_an_unknown_scheme_lists_the_known_ones():
    with pytest.raises(signing.SchemeError, match="aws-sigv4"):
        signing.sign({"scheme": "ed25519-magic"}, context())


def test_profile_bound_eip712_signing_commits_to_the_checked_message():
    if not signing.available("secp256k1-eip712"):
        pytest.skip("eth-account, coincurve and msgpack are optional")
    from eth_account import Account
    from eth_account.messages import encode_typed_data

    key = "0x" + "11" * 32
    profile = {
        "scheme": "secp256k1-eip712",
        "domain": {"name": "Example", "version": "1", "chainId": 1,
                   "verifyingContract": "0x0000000000000000000000000000000000000000"},
        "types": {"Agent": [{"name": "nonce", "type": "uint64"}]},
        "primary_type": "Agent",
        "payload_policy": {"actions": {"one": {
            "methods": ["SIGN"], "paths": ["/"],
            "required": ["nonce"], "max": {"nonce": 100}}}},
    }
    message = {"nonce": 7}
    got = signing.sign(profile, context(secret=key, body=json.dumps(message)))
    structured = encode_typed_data(full_message={
        "types": profile["types"], "domain": profile["domain"],
        "primaryType": profile["primary_type"], "message": message})
    recovered = Account.recover_message(
        structured, signature=bytes.fromhex(got[2:]))
    assert recovered == Account.from_key(key).address


# -- key encoding and the timestamp that has to match ----------------------
#
# A service that issues a base64 key signs with the DECODED bytes. Signing the
# text of one produces a valid-looking signature over the wrong key, which the
# far side rejects with nothing to say why.

def _ctx(secret, **config):
    return signing.Context(
        secret=secret, method="GET", url="https://api.test/v3/accounts/me",
        headers={}, body="", config=config, nonce=1, now=1_757_000_000.0)


def test_a_base64_key_is_decoded_before_it_is_used():
    import base64 as b64, hashlib, hmac as hmac_mod

    raw = b"\x00\x01\x02binary key bytes\xff"
    stored = b64.b64encode(raw).decode()
    ctx = _ctx(stored, scheme="hmac", template="{method}{path}",
               digest="sha512", encoding="base64", key_encoding="base64")

    got = signing.hmac_scheme(ctx)

    want = b64.b64encode(hmac_mod.new(
        raw, b"GET/v3/accounts/me", hashlib.sha512).digest()).decode()
    assert got == want
    assert got != signing.hmac_scheme(_ctx(
        stored, scheme="hmac", template="{method}{path}", digest="sha512",
        encoding="base64")), "the default must still sign the text"


def test_a_key_that_says_base64_and_is_not_is_refused_by_name():
    ctx = _ctx("not base64 at all!!", scheme="hmac", template="{method}",
               key_encoding="base64")

    with pytest.raises(signing.SchemeError, match="does not decode"):
        signing.hmac_scheme(ctx)


def test_an_unknown_key_encoding_is_refused():
    with pytest.raises(signing.SchemeError, match="no such key encoding"):
        signing.hmac_scheme(_ctx("x", scheme="hmac", template="{method}",
                                 key_encoding="rot13"))


def test_the_timestamp_header_carries_the_instant_that_was_signed():
    """The far side re-derives the message from the header, so the value sent
    has to be the value signed — not one the caller guessed a moment before."""
    ctx = _ctx("secret", scheme="hmac", template="{method}{path}{ts_ms}",
               timestamp_header="X-AUTH-TIMESTAMP")

    signing.hmac_scheme(ctx)

    assert ctx.headers["X-AUTH-TIMESTAMP"] == "1757000000000"


def test_no_timestamp_header_is_added_unless_the_profile_asks():
    ctx = _ctx("secret", scheme="hmac", template="{method}")
    signing.hmac_scheme(ctx)
    assert ctx.headers == {}


def test_the_timestamp_variable_may_be_seconds_instead():
    ctx = _ctx("secret", scheme="hmac", template="{method}{ts}",
               timestamp_header="X-TS", timestamp_variable="ts")
    signing.hmac_scheme(ctx)
    assert ctx.headers["X-TS"] == "1757000000"


def test_the_public_half_of_a_key_pair_is_placed_for_the_caller():
    """Most REST services send an identifier beside the signature. It is public —
    it travels in the clear on every request — so it belongs in the profile,
    not pasted into every call by whoever is making one."""
    ctx = _ctx("secret", scheme="hmac", template="{method}{path}",
               api_key_header="X-AUTH-APIKEY",
               key_id="765be18b-0000-0000-0000-000000000000")

    signature = signing.hmac_scheme(ctx)

    assert ctx.headers["X-AUTH-APIKEY"] == "765be18b-0000-0000-0000-000000000000"
    assert len(signature) > 0


def test_an_api_key_header_with_no_key_is_refused_rather_than_sent_empty():
    """An empty identifier is a 401 the caller has to guess the cause of."""
    ctx = _ctx("secret", scheme="hmac", template="{method}",
               api_key_header="X-AUTH-APIKEY")

    with pytest.raises(signing.SchemeError, match="no 'key_id'"):
        signing.hmac_scheme(ctx)


def test_no_api_key_header_is_added_unless_the_profile_asks():
    ctx = _ctx("secret", scheme="hmac", template="{method}", key_id="unused")
    signing.hmac_scheme(ctx)
    assert ctx.headers == {}
