"""Unit tests for the JSON DSL condition evaluator.

Covers all 20+ operators, path resolution, logical combinators,
array operators, and error handling.  No I/O — pure Python.
"""

from __future__ import annotations

import pytest

from waf_shared.domain.errors.domain_errors import DSLValidationError
from waf_reasoning.dsl_evaluator import (
    _resolve_path,
    _to_bool,
    evaluate_condition,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_RULE = "TEST-001"


def _eval(condition: dict, properties: dict) -> bool:
    return evaluate_condition(_RULE, condition, properties)


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestResolvePath:
    def test_top_level_key(self) -> None:
        assert _resolve_path("name", {"name": "vm1"}) == "vm1"

    def test_nested_key(self) -> None:
        assert _resolve_path("properties.sku", {"properties": {"sku": "Standard"}}) == "Standard"

    def test_deeply_nested(self) -> None:
        props = {"a": {"b": {"c": 42}}}
        assert _resolve_path("a.b.c", props) == 42

    def test_missing_top_level_returns_none(self) -> None:
        assert _resolve_path("missing", {}) is None

    def test_missing_nested_returns_none(self) -> None:
        assert _resolve_path("a.b.c", {"a": {}}) is None

    def test_list_index_access(self) -> None:
        props = {"zones": ["1", "2", "3"]}
        assert _resolve_path("zones.0", props) == "1"
        assert _resolve_path("zones.2", props) == "3"

    def test_list_out_of_range_returns_none(self) -> None:
        assert _resolve_path("zones.99", {"zones": ["1"]}) is None

    def test_non_numeric_index_on_list_returns_none(self) -> None:
        assert _resolve_path("zones.foo", {"zones": ["1"]}) is None

    def test_intermediate_none_short_circuits(self) -> None:
        assert _resolve_path("a.b.c", {"a": None}) is None

    def test_intermediate_non_dict_returns_none(self) -> None:
        assert _resolve_path("a.b", {"a": "string"}) is None

    def test_empty_path_key_not_found_returns_none(self) -> None:
        # "".split(".") == [""] — looks up dict key "" which is absent → None
        assert _resolve_path("", {"x": 1}) is None


# ---------------------------------------------------------------------------
# _to_bool helper
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestToBool:
    def test_true_bool(self) -> None:
        assert _to_bool(True) is True

    def test_false_bool(self) -> None:
        assert _to_bool(False) is False

    @pytest.mark.parametrize("s", ["true", "True", "TRUE", "1", "yes", "enabled"])
    def test_truthy_strings(self, s: str) -> None:
        assert _to_bool(s) is True

    @pytest.mark.parametrize("s", ["false", "False", "0", "no", "disabled", ""])
    def test_falsy_strings(self, s: str) -> None:
        assert _to_bool(s) is False

    def test_nonzero_int(self) -> None:
        assert _to_bool(1) is True

    def test_zero_int(self) -> None:
        assert _to_bool(0) is False

    def test_none(self) -> None:
        assert _to_bool(None) is False


# ---------------------------------------------------------------------------
# Special operators
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSpecialOperators:
    def test_always_pass(self) -> None:
        assert _eval({"op": "always_pass"}, {}) is True

    def test_always_fail(self) -> None:
        assert _eval({"op": "always_fail"}, {}) is False


# ---------------------------------------------------------------------------
# Existence operators
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestExistenceOperators:
    def test_exists_present(self) -> None:
        assert _eval({"op": "exists", "path": "name"}, {"name": "vm"}) is True

    def test_exists_missing(self) -> None:
        assert _eval({"op": "exists", "path": "name"}, {}) is False

    def test_exists_null_value_is_false(self) -> None:
        assert _eval({"op": "exists", "path": "val"}, {"val": None}) is False

    def test_not_null_alias(self) -> None:
        assert _eval({"op": "not_null", "path": "val"}, {"val": "x"}) is True

    def test_is_null_missing_key(self) -> None:
        assert _eval({"op": "is_null", "path": "val"}, {}) is True

    def test_is_null_none_value(self) -> None:
        assert _eval({"op": "is_null", "path": "val"}, {"val": None}) is True

    def test_is_null_present_value(self) -> None:
        assert _eval({"op": "is_null", "path": "val"}, {"val": "x"}) is False


# ---------------------------------------------------------------------------
# Equality / inequality
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestEqualityOperators:
    def test_eq_string_match(self) -> None:
        assert _eval({"op": "eq", "path": "tier", "value": "Standard"}, {"tier": "Standard"}) is True

    def test_eq_string_mismatch(self) -> None:
        assert _eval({"op": "eq", "path": "tier", "value": "Standard"}, {"tier": "Basic"}) is False

    def test_eq_integer(self) -> None:
        assert _eval({"op": "eq", "path": "count", "value": 3}, {"count": 3}) is True

    def test_eq_none(self) -> None:
        assert _eval({"op": "eq", "path": "val", "value": None}, {"val": None}) is True

    def test_eq_list_empty(self) -> None:
        assert _eval({"op": "eq", "path": "zones", "value": []}, {"zones": []}) is True

    def test_ne_match(self) -> None:
        assert _eval({"op": "ne", "path": "tier", "value": "Basic"}, {"tier": "Standard"}) is True

    def test_ne_mismatch(self) -> None:
        assert _eval({"op": "ne", "path": "tier", "value": "Standard"}, {"tier": "Standard"}) is False


# ---------------------------------------------------------------------------
# Membership operators
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestMembershipOperators:
    def test_in_match(self) -> None:
        assert _eval(
            {"op": "in", "path": "sku", "values": ["Standard", "Premium"]},
            {"sku": "Standard"},
        ) is True

    def test_in_no_match(self) -> None:
        assert _eval(
            {"op": "in", "path": "sku", "values": ["Standard", "Premium"]},
            {"sku": "Basic"},
        ) is False

    def test_in_missing_values_raises(self) -> None:
        with pytest.raises(DSLValidationError):
            _eval({"op": "in", "path": "sku"}, {"sku": "Standard"})

    def test_not_in_match(self) -> None:
        assert _eval(
            {"op": "not_in", "path": "sku", "values": ["Basic"]},
            {"sku": "Standard"},
        ) is True

    def test_not_in_no_match(self) -> None:
        assert _eval(
            {"op": "not_in", "path": "sku", "values": ["Standard"]},
            {"sku": "Standard"},
        ) is False


# ---------------------------------------------------------------------------
# Numeric comparison operators
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestNumericOperators:
    def test_gt_true(self) -> None:
        assert _eval({"op": "gt", "path": "count", "value": 0}, {"count": 5}) is True

    def test_gt_false(self) -> None:
        assert _eval({"op": "gt", "path": "count", "value": 10}, {"count": 5}) is False

    def test_gt_equal_is_false(self) -> None:
        assert _eval({"op": "gt", "path": "count", "value": 5}, {"count": 5}) is False

    def test_gte_equal(self) -> None:
        assert _eval({"op": "gte", "path": "count", "value": 5}, {"count": 5}) is True

    def test_gte_greater(self) -> None:
        assert _eval({"op": "gte", "path": "count", "value": 3}, {"count": 5}) is True

    def test_gte_less(self) -> None:
        assert _eval({"op": "gte", "path": "count", "value": 10}, {"count": 5}) is False

    def test_lt_true(self) -> None:
        assert _eval({"op": "lt", "path": "count", "value": 10}, {"count": 5}) is True

    def test_lt_false(self) -> None:
        assert _eval({"op": "lt", "path": "count", "value": 3}, {"count": 5}) is False

    def test_lte_equal(self) -> None:
        assert _eval({"op": "lte", "path": "count", "value": 5}, {"count": 5}) is True

    def test_lte_less(self) -> None:
        assert _eval({"op": "lte", "path": "count", "value": 10}, {"count": 5}) is True

    def test_lte_greater(self) -> None:
        assert _eval({"op": "lte", "path": "count", "value": 3}, {"count": 5}) is False

    def test_numeric_op_on_string_returns_false(self) -> None:
        assert _eval({"op": "gt", "path": "val", "value": 0}, {"val": "five"}) is False

    def test_numeric_op_on_none_returns_false(self) -> None:
        assert _eval({"op": "gt", "path": "val", "value": 0}, {"val": None}) is False

    def test_float_comparison(self) -> None:
        assert _eval({"op": "gt", "path": "score", "value": 0.5}, {"score": 0.9}) is True


# ---------------------------------------------------------------------------
# String operators
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestStringOperators:
    def test_contains_case_insensitive_default(self) -> None:
        assert _eval(
            {"op": "contains", "path": "name", "value": "prod"},
            {"name": "PRODUCTION-vm"},
        ) is True

    def test_contains_case_sensitive_false(self) -> None:
        assert _eval(
            {"op": "contains", "path": "name", "value": "Prod", "ci": False},
            {"name": "production-vm"},
        ) is False

    def test_contains_non_string_returns_false(self) -> None:
        assert _eval({"op": "contains", "path": "val", "value": "x"}, {"val": 123}) is False

    def test_starts_with_match(self) -> None:
        assert _eval(
            {"op": "starts_with", "path": "id", "value": "/subscriptions/"},
            {"id": "/subscriptions/abc123"},
        ) is True

    def test_starts_with_ci(self) -> None:
        assert _eval(
            {"op": "starts_with", "path": "id", "value": "/SUBSCRIPTIONS/", "ci": True},
            {"id": "/subscriptions/abc123"},
        ) is True

    def test_starts_with_no_match(self) -> None:
        assert _eval(
            {"op": "starts_with", "path": "id", "value": "/tenants/"},
            {"id": "/subscriptions/abc"},
        ) is False

    def test_starts_with_non_string_returns_false(self) -> None:
        assert _eval({"op": "starts_with", "path": "val", "value": "/"}, {"val": 42}) is False


# ---------------------------------------------------------------------------
# Boolean operator
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestBoolEqOperator:
    def test_bool_eq_true_true(self) -> None:
        assert _eval({"op": "bool_eq", "path": "enabled", "value": True}, {"enabled": True}) is True

    def test_bool_eq_string_true(self) -> None:
        assert _eval({"op": "bool_eq", "path": "enabled", "value": True}, {"enabled": "true"}) is True

    def test_bool_eq_int_truthy(self) -> None:
        assert _eval({"op": "bool_eq", "path": "enabled", "value": True}, {"enabled": 1}) is True

    def test_bool_eq_false_false(self) -> None:
        assert _eval({"op": "bool_eq", "path": "enabled", "value": False}, {"enabled": False}) is True

    def test_bool_eq_mismatch(self) -> None:
        assert _eval({"op": "bool_eq", "path": "enabled", "value": True}, {"enabled": False}) is False


# ---------------------------------------------------------------------------
# Length operators
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestLengthOperators:
    def test_length_eq_list(self) -> None:
        assert _eval({"op": "length_eq", "path": "zones", "value": 3}, {"zones": [1, 2, 3]}) is True

    def test_length_eq_string(self) -> None:
        assert _eval({"op": "length_eq", "path": "name", "value": 3}, {"name": "abc"}) is True

    def test_length_eq_dict(self) -> None:
        assert _eval({"op": "length_eq", "path": "tags", "value": 2}, {"tags": {"a": 1, "b": 2}}) is True

    def test_length_eq_wrong_count(self) -> None:
        assert _eval({"op": "length_eq", "path": "zones", "value": 2}, {"zones": [1, 2, 3]}) is False

    def test_length_gte_match(self) -> None:
        assert _eval({"op": "length_gte", "path": "items", "value": 1}, {"items": [1, 2]}) is True

    def test_length_gte_exact(self) -> None:
        assert _eval({"op": "length_gte", "path": "items", "value": 2}, {"items": [1, 2]}) is True

    def test_length_gte_fail(self) -> None:
        assert _eval({"op": "length_gte", "path": "items", "value": 5}, {"items": [1, 2]}) is False

    def test_length_lte_match(self) -> None:
        assert _eval({"op": "length_lte", "path": "items", "value": 5}, {"items": [1, 2]}) is True

    def test_length_lte_fail(self) -> None:
        assert _eval({"op": "length_lte", "path": "items", "value": 1}, {"items": [1, 2]}) is False

    def test_length_on_non_sequence_returns_false(self) -> None:
        assert _eval({"op": "length_eq", "path": "val", "value": 1}, {"val": 42}) is False


# ---------------------------------------------------------------------------
# Array element matching
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestArrayMatchingOperators:
    def test_any_match_true(self) -> None:
        props = {"items": [{"name": "a"}, {"name": "b"}]}
        assert _eval(
            {
                "op": "any_match",
                "path": "items",
                "condition": {"op": "eq", "path": "name", "value": "b"},
            },
            props,
        ) is True

    def test_any_match_false(self) -> None:
        props = {"items": [{"name": "a"}, {"name": "c"}]}
        assert _eval(
            {
                "op": "any_match",
                "path": "items",
                "condition": {"op": "eq", "path": "name", "value": "b"},
            },
            props,
        ) is False

    def test_any_match_empty_array_is_false(self) -> None:
        assert _eval(
            {"op": "any_match", "path": "items", "condition": {"op": "always_pass"}},
            {"items": []},
        ) is False

    def test_any_match_non_array_is_false(self) -> None:
        assert _eval(
            {"op": "any_match", "path": "val", "condition": {"op": "always_pass"}},
            {"val": "not a list"},
        ) is False

    def test_all_match_true(self) -> None:
        props = {"zones": [{"id": "1"}, {"id": "1"}]}
        assert _eval(
            {
                "op": "all_match",
                "path": "zones",
                "condition": {"op": "eq", "path": "id", "value": "1"},
            },
            props,
        ) is True

    def test_all_match_one_fails(self) -> None:
        props = {"zones": [{"id": "1"}, {"id": "2"}]}
        assert _eval(
            {
                "op": "all_match",
                "path": "zones",
                "condition": {"op": "eq", "path": "id", "value": "1"},
            },
            props,
        ) is False

    def test_all_match_empty_array_is_true(self) -> None:
        """all() of an empty sequence is vacuously true."""
        assert _eval(
            {"op": "all_match", "path": "items", "condition": {"op": "always_fail"}},
            {"items": []},
        ) is True


# ---------------------------------------------------------------------------
# Logical combinators
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestLogicalOperators:
    def test_and_all_true(self) -> None:
        cond = {
            "op": "and",
            "conditions": [
                {"op": "eq", "path": "a", "value": 1},
                {"op": "eq", "path": "b", "value": 2},
            ],
        }
        assert _eval(cond, {"a": 1, "b": 2}) is True

    def test_and_one_false(self) -> None:
        cond = {
            "op": "and",
            "conditions": [
                {"op": "eq", "path": "a", "value": 1},
                {"op": "eq", "path": "b", "value": 99},
            ],
        }
        assert _eval(cond, {"a": 1, "b": 2}) is False

    def test_and_short_circuits(self) -> None:
        """and: stops at first False — the second condition would fail even if evaluated."""
        cond = {
            "op": "and",
            "conditions": [
                {"op": "always_fail"},
                {"op": "always_pass"},  # never reached
            ],
        }
        assert _eval(cond, {}) is False

    def test_or_one_true(self) -> None:
        cond = {
            "op": "or",
            "conditions": [
                {"op": "eq", "path": "a", "value": 99},
                {"op": "eq", "path": "b", "value": 2},
            ],
        }
        assert _eval(cond, {"a": 1, "b": 2}) is True

    def test_or_all_false(self) -> None:
        cond = {
            "op": "or",
            "conditions": [
                {"op": "always_fail"},
                {"op": "always_fail"},
            ],
        }
        assert _eval(cond, {}) is False

    def test_not_inverts_true_to_false(self) -> None:
        assert _eval({"op": "not", "condition": {"op": "always_pass"}}, {}) is False

    def test_not_inverts_false_to_true(self) -> None:
        assert _eval({"op": "not", "condition": {"op": "always_fail"}}, {}) is True

    def test_nested_logical(self) -> None:
        cond = {
            "op": "and",
            "conditions": [
                {
                    "op": "or",
                    "conditions": [
                        {"op": "eq", "path": "env", "value": "prod"},
                        {"op": "eq", "path": "env", "value": "staging"},
                    ],
                },
                {"op": "exists", "path": "name"},
            ],
        }
        assert _eval(cond, {"env": "prod", "name": "vm1"}) is True
        assert _eval(cond, {"env": "dev", "name": "vm1"}) is False
        assert _eval(cond, {"env": "prod"}) is False


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestDSLErrors:
    def test_unknown_operator_raises(self) -> None:
        with pytest.raises(DSLValidationError, match="unknown DSL operator"):
            _eval({"op": "superpowers", "path": "x"}, {})

    def test_missing_op_raises(self) -> None:
        with pytest.raises(DSLValidationError, match="missing required 'op'"):
            _eval({"path": "x", "value": 1}, {})

    def test_non_dict_node_raises(self) -> None:
        with pytest.raises(DSLValidationError):
            _eval("not a dict", {})  # type: ignore[arg-type]

    def test_and_missing_conditions_raises(self) -> None:
        with pytest.raises(DSLValidationError, match="requires list field 'conditions'"):
            _eval({"op": "and"}, {})

    def test_or_missing_conditions_raises(self) -> None:
        with pytest.raises(DSLValidationError, match="requires list field 'conditions'"):
            _eval({"op": "or"}, {})

    def test_not_missing_condition_raises(self) -> None:
        with pytest.raises(DSLValidationError, match="requires object field 'condition'"):
            _eval({"op": "not"}, {})

    def test_any_match_missing_path_raises(self) -> None:
        with pytest.raises(DSLValidationError):
            _eval({"op": "any_match", "condition": {"op": "always_pass"}}, {})

    def test_evaluate_condition_wraps_outer_exception(self) -> None:
        """evaluate_condition wraps unexpected errors in DSLValidationError."""
        # Force an unexpected error by passing a non-serializable condition structure
        with pytest.raises(DSLValidationError):
            evaluate_condition("BAD-001", "this is not a dict", {})  # type: ignore[arg-type]

    def test_in_missing_values_key_raises(self) -> None:
        with pytest.raises(DSLValidationError):
            _eval({"op": "in", "path": "x"}, {"x": "a"})


# ---------------------------------------------------------------------------
# Real-world WAF rule scenarios
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRealWorldScenarios:
    def test_vm_no_availability_zones(self) -> None:
        """REL-VM-001: VM has no availability zones → FAIL (eq [])."""
        cond = {"op": "eq", "path": "zones", "value": []}
        assert _eval(cond, {"zones": []}) is True
        assert _eval(cond, {"zones": ["1", "2"]}) is False

    def test_storage_public_access(self) -> None:
        """SEC-STG-001: Storage has public access → FAIL."""
        cond = {
            "op": "and",
            "conditions": [
                {"op": "bool_eq", "path": "properties.allowBlobPublicAccess", "value": True},
            ],
        }
        assert _eval(cond, {"properties": {"allowBlobPublicAccess": True}}) is True
        assert _eval(cond, {"properties": {"allowBlobPublicAccess": False}}) is False

    def test_keyvault_soft_delete_disabled(self) -> None:
        """SEC-KV-001: Key Vault soft delete not enabled → FAIL."""
        cond = {
            "op": "not",
            "condition": {
                "op": "bool_eq",
                "path": "properties.enableSoftDelete",
                "value": True,
            },
        }
        assert _eval(cond, {"properties": {"enableSoftDelete": False}}) is True
        assert _eval(cond, {"properties": {"enableSoftDelete": True}}) is False

    def test_aks_rbac_disabled(self) -> None:
        """SEC-AKS-001: AKS cluster RBAC disabled → FAIL."""
        cond = {
            "op": "bool_eq",
            "path": "properties.enableRBAC",
            "value": False,
        }
        assert _eval(cond, {"properties": {"enableRBAC": False}}) is True
        assert _eval(cond, {"properties": {"enableRBAC": True}}) is False

    def test_sql_tde_not_configured(self) -> None:
        """SEC-SQL-002: SQL TDE status not 'Enabled' → FAIL."""
        cond = {
            "op": "or",
            "conditions": [
                {"op": "is_null", "path": "properties.transparentDataEncryption"},
                {
                    "op": "ne",
                    "path": "properties.transparentDataEncryption.status",
                    "value": "Enabled",
                },
            ],
        }
        assert _eval(cond, {"properties": {}}) is True
        assert _eval(cond, {"properties": {"transparentDataEncryption": {"status": "Disabled"}}}) is True
        assert _eval(cond, {"properties": {"transparentDataEncryption": {"status": "Enabled"}}}) is False

    def test_network_security_group_open_ssh(self) -> None:
        """SEC-NSG-001: NSG allows SSH from any source."""
        cond = {
            "op": "any_match",
            "path": "properties.securityRules",
            "condition": {
                "op": "and",
                "conditions": [
                    {"op": "eq", "path": "properties.destinationPortRange", "value": "22"},
                    {"op": "eq", "path": "properties.sourceAddressPrefix", "value": "*"},
                    {"op": "eq", "path": "properties.access", "value": "Allow"},
                    {"op": "eq", "path": "properties.direction", "value": "Inbound"},
                ],
            },
        }
        props = {
            "properties": {
                "securityRules": [
                    {
                        "properties": {
                            "destinationPortRange": "22",
                            "sourceAddressPrefix": "*",
                            "access": "Allow",
                            "direction": "Inbound",
                        }
                    }
                ]
            }
        }
        assert _eval(cond, props) is True

        # Restricted source: only MY_IP
        props["properties"]["securityRules"][0]["properties"]["sourceAddressPrefix"] = "10.0.0.1/32"
        assert _eval(cond, props) is False
