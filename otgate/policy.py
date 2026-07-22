"""Loading and validation of policies from YAML.

A policy is a list of per-tag rules (see :mod:`otgate.models`). This module
turns a YAML document into a validated :class:`~otgate.models.Policy`, raising a
:class:`PolicyError` with an actionable message on anything malformed — an
unknown access level, ``max_rate`` without ``rate_interval``, an inverted
range, a broken interlock, etc. Nothing is silently dropped: a policy that does
not load is a policy the operator must fix.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from otgate.models import (
    INTERLOCK_OPERATORS,
    Access,
    Interlock,
    Policy,
    Rule,
    Scalar,
)


class PolicyError(ValueError):
    """Raised when a policy document is malformed or semantically invalid."""


def load_policy(path: str | Path) -> Policy:
    """Load and validate a policy from a YAML file.

    Args:
        path: path to a YAML policy file.

    Returns:
        A validated :class:`~otgate.models.Policy`.

    Raises:
        PolicyError: if the file is missing, is not valid YAML, or violates any
            policy validation rule.
    """
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"cannot read policy file {str(path)!r}: {exc}") from exc

    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"invalid YAML in {str(path)!r}: {exc}") from exc

    return parse_policy(raw)


def parse_policy(raw: object) -> Policy:
    """Validate an already-parsed YAML structure into a :class:`Policy`.

    Kept separate from :func:`load_policy` so policies can be validated from an
    in-memory structure (e.g. in tests) without touching the filesystem.
    """
    if raw is None:
        raise PolicyError("policy is empty (expected a list of rules)")
    if not isinstance(raw, list):
        raise PolicyError(
            f"policy must be a list of rules, got {type(raw).__name__}"
        )

    rules: dict[str, Rule] = {}
    for index, item in enumerate(raw):
        rule = _parse_rule(item, index)
        if rule.tag in rules:
            raise PolicyError(f"rule #{index}: duplicate tag {rule.tag!r}")
        rules[rule.tag] = rule

    return Policy(rules=rules)


# --- internals ---

_ALLOWED_RULE_KEYS = {
    "tag",
    "access",
    "value_range",
    "max_rate",
    "rate_interval",
    "interlocks",
}
_ALLOWED_INTERLOCK_KEYS = {"tag", "condition", "action"}


def _parse_rule(item: object, index: int) -> Rule:
    where = f"rule #{index}"
    if not isinstance(item, dict):
        raise PolicyError(f"{where}: each rule must be a mapping, got {type(item).__name__}")

    unknown = set(item) - _ALLOWED_RULE_KEYS
    if unknown:
        raise PolicyError(f"{where}: unknown key(s): {', '.join(sorted(unknown))}")

    # tag
    tag = item.get("tag")
    if not isinstance(tag, str) or not tag.strip():
        raise PolicyError(f"{where}: 'tag' is required and must be a non-empty string")
    where = f"rule {tag!r}"

    # access
    access_raw = item.get("access")
    if access_raw is None:
        raise PolicyError(f"{where}: 'access' is required")
    try:
        access = Access(access_raw)
    except ValueError:
        allowed = ", ".join(a.value for a in Access)
        raise PolicyError(
            f"{where}: unknown access {access_raw!r} (allowed: {allowed})"
        ) from None

    value_range = _parse_value_range(item.get("value_range"), where)
    max_rate, rate_interval = _parse_rate(
        item.get("max_rate"), item.get("rate_interval"), where
    )
    interlocks = _parse_interlocks(item.get("interlocks"), where)

    return Rule(
        tag=tag,
        access=access,
        value_range=value_range,
        max_rate=max_rate,
        rate_interval=rate_interval,
        interlocks=interlocks,
    )


def _parse_value_range(raw: object, where: str) -> tuple[float, float] | None:
    if raw is None:
        return None
    if not isinstance(raw, (list, tuple)) or len(raw) != 2:
        raise PolicyError(f"{where}: 'value_range' must be a list of exactly two numbers")
    lo, hi = raw
    if isinstance(lo, bool) or isinstance(hi, bool) or not _is_number(lo) or not _is_number(hi):
        raise PolicyError(f"{where}: 'value_range' bounds must be numbers")
    lo, hi = float(lo), float(hi)
    if lo > hi:
        raise PolicyError(
            f"{where}: 'value_range' lower bound {lo} is greater than upper bound {hi}"
        )
    return (lo, hi)


def _parse_rate(
    max_rate_raw: object, rate_interval_raw: object, where: str
) -> tuple[float | None, float | None]:
    if max_rate_raw is None:
        if rate_interval_raw is not None:
            raise PolicyError(
                f"{where}: 'rate_interval' set without 'max_rate' (has no effect)"
            )
        return None, None

    if isinstance(max_rate_raw, bool) or not _is_number(max_rate_raw):
        raise PolicyError(f"{where}: 'max_rate' must be a number")
    max_rate = float(max_rate_raw)
    if max_rate <= 0:
        raise PolicyError(f"{where}: 'max_rate' must be positive, got {max_rate}")

    if rate_interval_raw is None:
        raise PolicyError(f"{where}: 'max_rate' requires 'rate_interval' (seconds)")
    if isinstance(rate_interval_raw, bool) or not _is_number(rate_interval_raw):
        raise PolicyError(f"{where}: 'rate_interval' must be a number")
    rate_interval = float(rate_interval_raw)
    if rate_interval <= 0:
        raise PolicyError(f"{where}: 'rate_interval' must be positive, got {rate_interval}")

    return max_rate, rate_interval


def _parse_interlocks(raw: object, where: str) -> tuple[Interlock, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise PolicyError(f"{where}: 'interlocks' must be a list")

    interlocks: list[Interlock] = []
    for i, item in enumerate(raw):
        ctx = f"{where}: interlock #{i}"
        if not isinstance(item, dict):
            raise PolicyError(f"{ctx}: must be a mapping")
        unknown = set(item) - _ALLOWED_INTERLOCK_KEYS
        if unknown:
            raise PolicyError(f"{ctx}: unknown key(s): {', '.join(sorted(unknown))}")

        tag = item.get("tag")
        if not isinstance(tag, str) or not tag.strip():
            raise PolicyError(f"{ctx}: 'tag' is required and must be a non-empty string")

        condition = item.get("condition")
        if not isinstance(condition, str):
            raise PolicyError(f"{ctx}: 'condition' is required and must be a string")
        operator, threshold = _parse_condition(condition, ctx)

        action = item.get("action", "deny")
        if action != "deny":
            raise PolicyError(
                f"{ctx}: unsupported action {action!r} (only 'deny' is supported in v0.1)"
            )

        interlocks.append(
            Interlock(tag=tag, operator=operator, threshold=threshold, action=action)
        )
    return tuple(interlocks)


def _parse_condition(condition: str, ctx: str) -> tuple[str, Scalar]:
    """Parse a condition string like ``"== true"`` or ``">= 90"``.

    Returns the operator and a scalar threshold (bool if the operand parses as a
    boolean literal, otherwise a float).
    """
    text = condition.strip()
    # Longest operators first so ">=" is matched before ">".
    for op in sorted(INTERLOCK_OPERATORS, key=len, reverse=True):
        if text.startswith(op):
            operand = text[len(op):].strip()
            if not operand:
                raise PolicyError(f"{ctx}: condition {condition!r} is missing an operand")
            return op, _parse_operand(operand, condition, ctx)
    raise PolicyError(
        f"{ctx}: condition {condition!r} must start with one of "
        f"{', '.join(INTERLOCK_OPERATORS)}"
    )


def _parse_operand(operand: str, condition: str, ctx: str) -> Scalar:
    low = operand.lower()
    if low in ("true", "false"):
        return low == "true"
    try:
        return float(operand)
    except ValueError:
        raise PolicyError(
            f"{ctx}: condition {condition!r} has a non-numeric, non-boolean operand "
            f"{operand!r}"
        ) from None


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)
