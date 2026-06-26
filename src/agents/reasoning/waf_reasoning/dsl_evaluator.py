"""JSON DSL condition evaluator for deterministic WAF rules.

The ``condition_dsl`` column in ``waf_rules`` is JSONB — not a Python expression
string.  No eval() or exec() is ever called here (see migration 0003_rules_and_findings.py).

Supported operators:
  Path access:
    exists        — path exists and value is not None
    is_null       — path is missing or None
    not_null      — alias for exists

  Comparison:
    eq            — equals value (type-flexible; uses ==)
    ne            — not equals value
    in            — value is in list of values
    not_in        — value not in list of values
    gt            — greater than (numeric)
    gte           — greater than or equal (numeric)
    lt            — less than (numeric)
    lte           — less than or equal (numeric)
    contains      — string contains value (case-insensitive if ci=true)
    starts_with   — string starts with value
    bool_eq       — value equals boolean (resolves truthy strings)

  Array:
    length_eq     — array / string length == n
    length_gte    — array / string length >= n
    length_lte    — array / string length <= n
    any_match     — any element in array satisfies sub-condition
    all_match     — all elements in array satisfy sub-condition

  Logical:
    and           — all sub-conditions true
    or            — any sub-condition true
    not           — negate sub-condition

  Special:
    always_pass   — unconditionally true (for rules with no deterministic check)
    always_fail   — unconditionally false

DSLValidationError is raised if the DSL structure is malformed or references an
unknown operator.  Individual missing paths return None (not an error).
"""

from __future__ import annotations

from typing import Any

from waf_shared.domain.errors.domain_errors import DSLValidationError


def evaluate_condition(
    rule_id: str,
    condition: dict[str, Any],
    properties: dict[str, Any],
) -> bool:
    """Evaluate one DSL condition tree against resource properties.

    Returns True (PASS) or False (FAIL).
    Raises DSLValidationError on malformed condition structure.
    """
    try:
        return _eval(condition, properties)
    except DSLValidationError:
        raise
    except Exception as exc:
        raise DSLValidationError(rule_id, f"unexpected error during DSL evaluation: {exc}") from exc


# ── Internal evaluator ─────────────────────────────────────────────────────────


def _eval(node: dict[str, Any], props: dict[str, Any]) -> bool:
    if not isinstance(node, dict):
        raise DSLValidationError("unknown", "DSL condition must be a JSON object")

    op = node.get("op")
    if op is None:
        raise DSLValidationError("unknown", "DSL node is missing required 'op' field")

    # ── Logical combinators ────────────────────────────────────────────────────
    if op == "and":
        sub = _require_list(node, "conditions")
        return all(_eval(c, props) for c in sub)

    if op == "or":
        sub = _require_list(node, "conditions")
        return any(_eval(c, props) for c in sub)

    if op == "not":
        sub = _require_node(node, "condition")
        return not _eval(sub, props)

    # ── Special ────────────────────────────────────────────────────────────────
    if op == "always_pass":
        return True
    if op == "always_fail":
        return False

    # ── Array element matching ─────────────────────────────────────────────────
    if op in ("any_match", "all_match"):
        path = _require_str(node, "path")
        sub = _require_node(node, "condition")
        arr = _resolve_path(path, props)
        if not isinstance(arr, list):
            return False
        results = [_eval(sub, item) for item in arr]
        return any(results) if op == "any_match" else all(results)

    # ── All other operators require a 'path' ──────────────────────────────────
    path = _require_str(node, "path")
    val = _resolve_path(path, props)

    if op in ("exists", "not_null"):
        return val is not None

    if op == "is_null":
        return val is None

    if op == "eq":
        return val == node.get("value")

    if op == "ne":
        return val != node.get("value")

    if op == "in":
        list_key = "values" if "values" in node else "value"
        values = _require_list(node, list_key)
        return val in values

    if op == "not_in":
        list_key = "values" if "values" in node else "value"
        values = _require_list(node, list_key)
        return val not in values

    if op == "gt":
        target = node.get("value")
        return isinstance(val, int | float) and val > target  # type: ignore[operator]

    if op == "gte":
        target = node.get("value")
        return isinstance(val, int | float) and val >= target  # type: ignore[operator]

    if op == "lt":
        target = node.get("value")
        return isinstance(val, int | float) and val < target  # type: ignore[operator]

    if op == "lte":
        target = node.get("value")
        return isinstance(val, int | float) and val <= target  # type: ignore[operator]

    if op == "contains":
        target = node.get("value", "")
        ci = node.get("ci", True)
        if not isinstance(val, str):
            return False
        return (target.lower() in val.lower()) if ci else (target in val)

    if op == "starts_with":
        target = node.get("value", "")
        ci = node.get("ci", False)
        if not isinstance(val, str):
            return False
        return (val.lower().startswith(target.lower())) if ci else val.startswith(target)

    if op == "bool_eq":
        target = node.get("value")
        return _to_bool(val) == bool(target)

    if op == "length_eq":
        n = node.get("value")
        return isinstance(val, list | str | dict) and len(val) == n  # type: ignore[arg-type]

    if op == "length_gte":
        n = node.get("value")
        return isinstance(val, list | str | dict) and len(val) >= n  # type: ignore[operator]

    if op == "length_lte":
        n = node.get("value")
        return isinstance(val, list | str | dict) and len(val) <= n  # type: ignore[operator]

    raise DSLValidationError("unknown", f"unknown DSL operator '{op}'")


# ── Path resolution ────────────────────────────────────────────────────────────


def _resolve_path(path: str, obj: Any) -> Any:
    """Traverse a dot-separated path into a nested dict.

    Returns None for missing keys — never raises.
    Supports numeric indices for list access (e.g. "items.0.name").
    """
    parts = path.split(".")
    current = obj
    for part in parts:
        if current is None:
            return None
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return current


# ── Helpers ────────────────────────────────────────────────────────────────────


def _require_str(node: dict[str, Any], key: str) -> str:
    val = node.get(key)
    if not isinstance(val, str):
        raise DSLValidationError("unknown", f"DSL node requires string field '{key}'")
    return val


def _require_list(node: dict[str, Any], key: str) -> list[Any]:
    val = node.get(key)
    if not isinstance(val, list):
        raise DSLValidationError("unknown", f"DSL node requires list field '{key}'")
    return val


def _require_node(node: dict[str, Any], key: str) -> dict[str, Any]:
    val = node.get(key)
    if not isinstance(val, dict):
        raise DSLValidationError("unknown", f"DSL node requires object field '{key}'")
    return val


def _to_bool(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ("true", "1", "yes", "enabled")
    return bool(val)
