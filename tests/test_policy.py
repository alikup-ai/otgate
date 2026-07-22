"""Policy loading and validation tests."""

from __future__ import annotations

import pytest

from otgate.models import Access
from otgate.policy import PolicyError, load_policy, parse_policy

from conftest import ESD, POLICY_PATH, PV, SP


def test_valid_policy_loads():
    policy = load_policy(POLICY_PATH)
    assert set(policy.rules) == {SP, PV, "ns=2;s=Reactor.PIC201.PV", ESD}
    sp = policy.get(SP)
    assert sp.access is Access.WRITE_WITH_APPROVAL
    assert sp.value_range == (40.0, 80.0)
    assert sp.max_rate == 5.0
    assert sp.rate_interval == 60.0
    assert len(sp.interlocks) == 1
    assert sp.interlocks[0].tag == ESD
    assert sp.interlocks[0].operator == "=="
    assert sp.interlocks[0].threshold is True


def test_visible_tags_excludes_deny():
    policy = parse_policy(
        [
            {"tag": "a", "access": "read"},
            {"tag": "b", "access": "deny"},
            {"tag": "c", "access": "write"},
        ]
    )
    assert policy.visible_tags() == ["a", "c"]


def test_missing_file_error():
    with pytest.raises(PolicyError, match="cannot read"):
        load_policy("does/not/exist.yaml")


def test_invalid_yaml_error(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("tag: [unclosed", encoding="utf-8")
    with pytest.raises(PolicyError, match="invalid YAML"):
        load_policy(bad)


def test_empty_policy_error():
    with pytest.raises(PolicyError, match="empty"):
        parse_policy(None)


def test_non_list_policy_error():
    with pytest.raises(PolicyError, match="must be a list"):
        parse_policy({"tag": "t"})


def test_missing_tag_error():
    with pytest.raises(PolicyError, match="'tag' is required"):
        parse_policy([{"access": "read"}])


def test_missing_access_error():
    with pytest.raises(PolicyError, match="'access' is required"):
        parse_policy([{"tag": "t"}])


def test_unknown_access_error():
    with pytest.raises(PolicyError, match="unknown access"):
        parse_policy([{"tag": "t", "access": "sometimes"}])


def test_unknown_key_error():
    with pytest.raises(PolicyError, match="unknown key"):
        parse_policy([{"tag": "t", "access": "read", "typo": 1}])


def test_inverted_range_error():
    with pytest.raises(PolicyError, match="greater than"):
        parse_policy([{"tag": "t", "access": "write", "value_range": [80, 40]}])


def test_range_wrong_length_error():
    with pytest.raises(PolicyError, match="exactly two"):
        parse_policy([{"tag": "t", "access": "write", "value_range": [1, 2, 3]}])


def test_max_rate_without_interval_error():
    with pytest.raises(PolicyError, match="requires 'rate_interval'"):
        parse_policy([{"tag": "t", "access": "write", "max_rate": 5}])


def test_interval_without_max_rate_error():
    with pytest.raises(PolicyError, match="without 'max_rate'"):
        parse_policy([{"tag": "t", "access": "write", "rate_interval": 60}])


def test_negative_max_rate_error():
    with pytest.raises(PolicyError, match="must be positive"):
        parse_policy(
            [{"tag": "t", "access": "write", "max_rate": -1, "rate_interval": 60}]
        )


def test_bad_interlock_condition_operator_error():
    with pytest.raises(PolicyError, match="must start with"):
        parse_policy(
            [
                {
                    "tag": "t",
                    "access": "write",
                    "interlocks": [{"tag": "x", "condition": "?? 1"}],
                }
            ]
        )


def test_bad_interlock_operand_error():
    with pytest.raises(PolicyError, match="non-numeric"):
        parse_policy(
            [
                {
                    "tag": "t",
                    "access": "write",
                    "interlocks": [{"tag": "x", "condition": "== nope"}],
                }
            ]
        )


def test_unsupported_interlock_action_error():
    with pytest.raises(PolicyError, match="unsupported action"):
        parse_policy(
            [
                {
                    "tag": "t",
                    "access": "write",
                    "interlocks": [
                        {"tag": "x", "condition": ">= 1", "action": "force"}
                    ],
                }
            ]
        )


def test_duplicate_tag_error():
    with pytest.raises(PolicyError, match="duplicate tag"):
        parse_policy(
            [{"tag": "t", "access": "read"}, {"tag": "t", "access": "write"}]
        )


def test_operator_precedence_ge_over_gt():
    policy = parse_policy(
        [
            {
                "tag": "t",
                "access": "write",
                "interlocks": [{"tag": "x", "condition": ">= 90"}],
            }
        ]
    )
    il = policy.get("t").interlocks[0]
    assert il.operator == ">="
    assert il.threshold == 90.0
