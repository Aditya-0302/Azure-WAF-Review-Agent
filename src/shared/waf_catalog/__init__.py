"""WAF Catalog — Microsoft Well-Architected Framework governance layer.

Public API:
  WafCatalog      — singleton catalog for lookup and finding enrichment
  WafControl      — one official WAF recommendation record
  WafEnrichment   — enrichment payload to annotate a Finding
  compute_coverage — generate a CoverageReport for a rule set
  compute_gaps     — generate a GapReport identifying unmapped controls and rules
  build_traceability_matrix — Finding → Rule → WAF Control → Microsoft Guidance
  validate_catalog — CI validation; raises CatalogValidationError on failure
"""

from waf_catalog.catalog import WafCatalog, WafControl, WafEnrichment
from waf_catalog.coverage import CoverageReport, CoverageStatus, compute_coverage
from waf_catalog.gap_analyzer import GapReport, compute_gaps
from waf_catalog.traceability import TraceabilityEntry, build_traceability_matrix
from waf_catalog.validator import CatalogValidationError, validate_catalog

__all__ = [
    "WafCatalog",
    "WafControl",
    "WafEnrichment",
    "CoverageReport",
    "CoverageStatus",
    "compute_coverage",
    "GapReport",
    "compute_gaps",
    "TraceabilityEntry",
    "build_traceability_matrix",
    "CatalogValidationError",
    "validate_catalog",
]
