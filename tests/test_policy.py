from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urlencode

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from xenia import policy

# Two APIs, because they put their parameters in different places and both
# have to be checked. One takes JSON; the other is the shape where a signed
# request carries its parameters in the query string or a form body.

JSON_API = {"actions": {
    "create": {
        "methods": ["POST"], "paths": ["/v1/items"],
        "in": {"project": ["alpha"], "mode": ["standard", "queued"]},
        "equals": {"dryRun": True},
        "max": {"count": "10"},
    },
    "read": {"methods": ["GET"], "paths": ["/v1/account/*"]},
}}

FORM_API = {"actions": {
    "create": {
        "methods": ["POST"], "paths": ["/api/create"],
        "in": {"project": ["alpha"], "mode": ["standard"]},
        "equals": {"dryRun": "true"},
        "max": {"count": "10"},
    },
}}

JSON = {"Content-Type": "application/json"}
FORM = {"Content-Type": "application/x-www-form-urlencoded"}


def payload(**overrides):
    body = {"project": "alpha", "mode": "standard", "count": "2",
            "label": "nightly", "dryRun": True}
    body.update(overrides)
    return json.dumps(body)


def form_url(**overrides):
    params = {"project": "alpha", "mode": "standard", "count": "2",
              "dryRun": "true", "timestamp": "1757000000000"}
    params.update(overrides)
    return "https://api.test/api/create?" + urlencode(params)


# -- the allowlist ----------------------------------------------------------

def test_a_permitted_request_passes_and_names_the_rule():
    assert policy.check(JSON_API, "POST", "https://api.test/v1/items", JSON,
                        payload()) == "create"


def test_an_endpoint_nobody_listed_is_refused():
    """The refusal does not depend on anyone having thought of this endpoint.

    A denylist of known-bad paths fails open the day one is added.
    """
    with pytest.raises(policy.Denied, match="no action permits"):
        policy.check(JSON_API, "POST", "https://api.test/v1/projects/purge",
                     JSON, '{"project": "alpha"}')


def test_the_refusal_names_what_is_permitted_instead():
    with pytest.raises(policy.Denied) as raised:
        policy.check(JSON_API, "POST", "https://api.test/v1/transfer", JSON,
                     "{}")

    assert "create" in str(raised.value)
    assert "/v1/items" in str(raised.value)


def test_a_method_outside_the_action_is_refused():
    with pytest.raises(policy.Denied, match="no action permits"):
        policy.check(JSON_API, "DELETE", "https://api.test/v1/items", JSON,
                     payload())


def test_a_read_with_no_body_is_permitted():
    assert policy.check(JSON_API, "GET", "https://api.test/v1/account/usage",
                        {}, None) == "read"


# -- fields, in JSON --------------------------------------------------------

def test_a_value_outside_the_set_is_refused():
    with pytest.raises(policy.Denied, match="beta"):
        policy.check(JSON_API, "POST", "https://api.test/v1/items", JSON,
                     payload(project="beta"))


def test_values_are_matched_literally_and_not_normalised():
    """A normaliser that maps one wrong permits the wrong thing while reading
    as protection, so `Alpha` is not `alpha`."""
    with pytest.raises(policy.Denied):
        policy.check(JSON_API, "POST", "https://api.test/v1/items", JSON,
                     payload(project="Alpha"))


def test_a_value_over_the_cap_is_refused():
    with pytest.raises(policy.Denied, match="over the cap"):
        policy.check(JSON_API, "POST", "https://api.test/v1/items", JSON,
                     payload(count="500"))


def test_a_capped_field_that_is_absent_is_refused_not_assumed_small():
    body = json.loads(payload())
    body.pop("count")
    with pytest.raises(policy.Denied, match="absent"):
        policy.check(JSON_API, "POST", "https://api.test/v1/items", JSON,
                     json.dumps(body))


def test_a_mode_outside_the_allowlist_is_refused():
    """Nothing here is derived from other fields: a request is judged on what
    it actually contains."""
    with pytest.raises(policy.Denied, match="mode"):
        policy.check(JSON_API, "POST", "https://api.test/v1/items", JSON,
                     payload(mode="immediate"))


def test_a_required_flag_must_be_set():
    with pytest.raises(policy.Denied, match="dryRun"):
        policy.check(JSON_API, "POST", "https://api.test/v1/items", JSON,
                     payload(dryRun=False))


def test_every_item_in_a_batch_must_pass():
    batch = json.dumps([json.loads(payload()), json.loads(payload(count="99"))])
    with pytest.raises(policy.Denied, match="over the cap"):
        policy.check(JSON_API, "POST", "https://api.test/v1/items", JSON,
                     batch)


# -- fields, in a query string or a form body -------------------------------

def test_a_query_string_request_is_checked():
    """Reading only JSON would leave this shape unchecked while reporting
    that policy was in force."""
    assert policy.check(FORM_API, "POST", form_url(), {}, None) == "create"


def test_a_query_string_value_over_the_cap_is_refused():
    with pytest.raises(policy.Denied, match="over the cap"):
        policy.check(FORM_API, "POST", form_url(count="99"), {}, None)


def test_a_query_string_value_outside_the_set_is_refused():
    with pytest.raises(policy.Denied, match="beta"):
        policy.check(FORM_API, "POST", form_url(project="beta"), {}, None)


def test_a_form_encoded_body_is_checked():
    body = urlencode({"project": "alpha", "mode": "standard", "count": "2",
                      "dryRun": "true"})
    assert policy.check(FORM_API, "POST", "https://api.test/api/create", FORM,
                        body) == "create"


def test_a_form_encoded_body_over_the_cap_is_refused():
    body = urlencode({"project": "alpha", "mode": "standard", "count": "99",
                      "dryRun": "true"})
    with pytest.raises(policy.Denied, match="over the cap"):
        policy.check(FORM_API, "POST", "https://api.test/api/create", FORM,
                     body)


def test_a_string_true_and_a_json_true_mean_the_same_thing():
    """One encoding sends the text and the other the boolean. Telling them
    apart would pass everything in one of them."""
    body = urlencode({"project": "alpha", "mode": "standard", "count": "2",
                      "dryRun": "false"})
    with pytest.raises(policy.Denied, match="dryRun"):
        policy.check(FORM_API, "POST", "https://api.test/api/create", FORM,
                     body)


def test_an_unlisted_query_string_endpoint_is_refused():
    with pytest.raises(policy.Denied, match="no action permits"):
        policy.check(FORM_API, "POST",
                     "https://api.test/api/purge?project=alpha", {}, None)


# -- failing closed ---------------------------------------------------------

def test_a_body_that_will_not_parse_is_refused():
    with pytest.raises(policy.Unparsed, match="not the JSON"):
        policy.fields("POST", "https://api.test/v1/items", JSON,
                      "{not json at all")


def test_a_content_type_xenia_cannot_read_is_refused():
    with pytest.raises(policy.Unparsed, match="cannot read"):
        policy.fields("POST", "https://api.test/v1/items",
                      {"Content-Type": "application/octet-stream"},
                      "\\x00\\x01binary")


def test_a_body_that_is_not_an_object_is_refused():
    with pytest.raises(policy.Unparsed, match="must be an object"):
        policy.fields("POST", "https://api.test/v1/items", JSON,
                      '["just", "a"]')


def test_a_field_in_both_the_query_and_the_body_is_refused_as_ambiguous():
    """Which one the far side reads is not xenia's to guess, and guessing
    wrong applies a cap to a number nobody reads."""
    with pytest.raises(policy.Unparsed, match="both the query string"):
        policy.fields("POST", "https://api.test/v1/items?count=2", JSON,
                      '{"count": "99"}')


def test_the_same_value_in_both_places_is_not_ambiguous():
    rows = policy.fields("POST", "https://api.test/v1/items?count=1", JSON,
                         '{"count": "1"}')

    assert rows[0]["count"] == "1"


def test_a_policy_with_no_actions_permits_nothing():
    with pytest.raises(policy.Denied, match="permits nothing"):
        policy.check({"actions": {}}, "GET", "https://api.test/", {}, None)


def test_a_capped_field_that_is_not_a_number_is_refused():
    with pytest.raises(policy.Denied, match="not a number"):
        policy.check(FORM_API, "POST", form_url(count="lots"), {}, None)


# -- reading it back --------------------------------------------------------

def test_a_policy_can_be_described_in_words():
    described = policy.describe(JSON_API)

    assert any("create" in line and "count<=10" in line for line in described)
    assert any("read" in line for line in described)
