"""Configurable scoring weights for the WAF assessment scoring engine.

All magic numbers that influence score calculation live here and nowhere else.
Consumers import ``DEFAULT_SCORING_WEIGHTS`` for production use or construct a
custom ``ScoringWeights`` instance for testing or tenant-specific overrides.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScoringWeights:
    """Immutable scoring configuration consumed by ``ScoringEngine``.

    Attributes
    ----------
    severity_weights:
        Maps a finding / rule severity string to a numeric weight.
        Higher weights mean a failure on that rule deducts more from the
        compliance score.  All values must be positive.

    pillar_weights:
        Fixed fraction of the overall compliance score owned by each
        Well-Architected pillar.  Values should sum to 1.0; if they do
        not, the engine normalises automatically.

    resource_criticality:
        Per-resource-type multiplier applied to finding weights.  Resources
        that are more critical to business continuity receive a higher
        multiplier so failures on those resources reduce the pillar score
        more than equivalent failures on lower-criticality resources.
        Keys must be lowercase Azure resource-type strings.

    default_resource_criticality:
        Fallback multiplier for resource types not in ``resource_criticality``.
    """

    severity_weights: dict[str, float]
    pillar_weights: dict[str, float]
    resource_criticality: dict[str, float]
    default_resource_criticality: float = 1.0


# ---------------------------------------------------------------------------
# Default production weights — aligned with Microsoft WAF pillar guidance
# ---------------------------------------------------------------------------

DEFAULT_SCORING_WEIGHTS = ScoringWeights(
    # Rule / finding severity → numeric weight.
    # Critical = 10 (most impactful), Informational = 1 (advisory only).
    severity_weights={
        "critical": 10.0,
        "high": 7.0,
        "medium": 5.0,
        "low": 2.0,
        "informational": 1.0,
    },
    # Pillar → fraction of the overall compliance score.
    # Security leads at 30 % per Microsoft WAF guidance.
    # Reliability and Performance Efficiency share the second tier (20 % each).
    # Operational Excellence and Cost Optimization complete the model at 15 % each.
    pillar_weights={
        "security": 0.30,
        "reliability": 0.20,
        "performance_efficiency": 0.20,
        "operational_excellence": 0.15,
        "cost_optimization": 0.15,
    },
    # Resource type → criticality multiplier (keys in lowercase).
    # A multiplier of 1.5 means a critical finding on a Key Vault contributes
    # 10 × 1.5 = 15 weight units rather than the baseline 10.
    resource_criticality={
        # Tier 1 — highest business impact on breach or failure
        "microsoft.keyvault/vaults": 1.5,
        "microsoft.sql/servers": 1.5,
        "microsoft.sql/servers/databases": 1.4,
        "microsoft.network/applicationgateways": 1.4,
        "microsoft.storage/storageaccounts": 1.3,
        # Tier 2 — core workload services
        "microsoft.compute/virtualmachines": 1.2,
        "microsoft.web/sites": 1.2,
        "microsoft.containerservice/managedclusters": 1.2,
        "microsoft.documentdb/databaseaccounts": 1.2,
        "microsoft.servicebus/namespaces": 1.1,
        "microsoft.eventhub/namespaces": 1.1,
        "microsoft.cache/redis": 1.1,
        "microsoft.dbformysql/flexibleservers": 1.1,
        "microsoft.dbforpostgresql/flexibleservers": 1.1,
        # Tier 3 — supporting infrastructure
        "microsoft.compute/virtualmachinescalesets": 1.0,
        "microsoft.web/serverfarms": 1.0,
        "microsoft.network/loadbalancers": 0.9,
        "microsoft.network/networksecuritygroups": 0.9,
        "microsoft.insights/activitylogalerts": 0.9,
        "microsoft.cdn/profiles": 0.8,
        "microsoft.cdn/profiles/endpoints": 0.8,
        "microsoft.network/networkinterfaces": 0.7,
        "microsoft.network/publicipaddresses": 0.7,
        "microsoft.compute/disks": 0.6,
        "microsoft.compute/snapshots": 0.6,
    },
    default_resource_criticality=1.0,
)
