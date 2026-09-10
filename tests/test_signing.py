from __future__ import annotations

import calendar
import hashlib
import hmac
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
