"""Resource property compressor — reduces raw_properties for LLM prompt construction.

For deterministic rules the full properties are not needed; the DSL evaluator
accesses only the specific paths referenced in condition_dsl.

For LLM-assisted rules the compressor projects the raw Azure Resource Graph row
down to a minimal dict before injecting it into the LLM prompt.  Target budget
is ≤ 800 tokens per resource (vs. 3 000+ tokens uncompressed).

Path extraction uses the same dot-notation as the DSL evaluator; the compressor
recursively collects all ``path`` strings from a condition_dsl tree so we can
build the minimal property set for deterministic rules as well.
"""

from __future__ import annotations

import json
from typing import Any

# Top-level fields always included regardless of rule type.
_MANDATORY_FIELDS = frozenset(
    {"id", "name", "type", "location", "resourceGroup", "subscriptionId", "tenantId"}
)

# Maximum JSON character budget before hard truncation applies.
# Roughly 800 tokens × 4 chars/token.
_MAX_CHARS = 3_200


class PropertyCompressor:
    """Projects raw resource properties to only the fields relevant for a rule."""

    def compress_for_dsl(
        self,
        raw_properties: dict[str, Any],
        condition_dsl: dict[str, Any],
    ) -> dict[str, Any]:
        """Return a dict containing only paths referenced in the DSL tree.

        Always includes the mandatory identity fields.  Never returns None.
        """
        paths = _extract_paths(condition_dsl)
        return _project(raw_properties, paths, mandatory=True)

    def compress_for_llm(
        self,
        raw_properties: dict[str, Any],
        relevant_paths: list[str] | None = None,
    ) -> dict[str, Any]:
        """Return a dict projected to *relevant_paths* and capped to the token budget.

        If *relevant_paths* is None the whole properties dict is included but
        truncated at ``_MAX_CHARS`` bytes of JSON.
        """
        if relevant_paths:
            compressed = _project(raw_properties, relevant_paths, mandatory=True)
        else:
            compressed = {k: v for k, v in raw_properties.items()}
            # Always keep mandatory identity fields
            for f in _MANDATORY_FIELDS:
                if f in raw_properties:
                    compressed[f] = raw_properties[f]

        # Cap at budget
        serialised = json.dumps(compressed, default=str)
        if len(serialised) > _MAX_CHARS:
            # Progressively drop lower-priority keys until under budget.
            # Priority: mandatory > properties > tags > everything else
            compressed = _truncate_to_budget(compressed, _MAX_CHARS)

        return compressed


# ── Helpers ────────────────────────────────────────────────────────────────────


def _extract_paths(node: dict[str, Any]) -> list[str]:
    """Recursively collect all 'path' values from a DSL condition tree."""
    paths: list[str] = []
    if not isinstance(node, dict):
        return paths

    if "path" in node and isinstance(node["path"], str):
        paths.append(node["path"])

    for key in ("condition", "conditions"):
        child = node.get(key)
        if isinstance(child, dict):
            paths.extend(_extract_paths(child))
        elif isinstance(child, list):
            for item in child:
                if isinstance(item, dict):
                    paths.extend(_extract_paths(item))

    return paths


def _project(
    props: dict[str, Any],
    paths: list[str],
    *,
    mandatory: bool,
) -> dict[str, Any]:
    """Build a new dict containing only top-level keys referenced by *paths*.

    Dot-paths like ``"properties.sku"`` are included by extracting the top-level
    key ``"properties"`` (we keep the whole sub-tree to preserve nested access).
    """
    top_keys: set[str] = set()
    for path in paths:
        top_keys.add(path.split(".")[0])

    if mandatory:
        top_keys.update(_MANDATORY_FIELDS)

    return {k: v for k, v in props.items() if k in top_keys}


def _truncate_to_budget(
    props: dict[str, Any],
    max_chars: int,
) -> dict[str, Any]:
    """Drop lower-priority keys until the JSON serialisation fits the budget."""
    result = {k: props[k] for k in _MANDATORY_FIELDS if k in props}
    serialised = json.dumps(result, default=str)

    for key in ("properties",):
        if key in props and len(serialised) < max_chars:
            candidate = {**result, key: props[key]}
            s = json.dumps(candidate, default=str)
            if len(s) <= max_chars:
                result = candidate
                serialised = s
            else:
                # Truncate properties to a string summary
                summary = s[: max_chars - len(serialised) - 50]
                result[key] = {"_truncated": True, "_preview": summary}
                serialised = json.dumps(result, default=str)

    for key in ("tags", "sku", "kind", "identity", "zones"):
        if key in props and len(serialised) < max_chars:
            candidate = {**result, key: props[key]}
            s = json.dumps(candidate, default=str)
            if len(s) <= max_chars:
                result = candidate
                serialised = s

    return result
