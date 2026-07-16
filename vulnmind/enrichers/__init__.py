"""Offline-first exploit-intelligence data sources.

The individual modules intentionally return normalized lookup data rather
than modifying ``Finding`` objects.  Keeping the data-access layer separate
makes it possible for the CLI to apply confidence and priority policy in one
place without coupling cache/network behavior to the finding model.
"""

from vulnmind.enrichers.exploitdb import lookup_cves as lookup_exploitdb_cves
from vulnmind.enrichers.kev import lookup_cves as lookup_kev_cves
from vulnmind.enrichers.intelligence import enrich_with_exploit_intelligence

__all__ = [
    "enrich_with_exploit_intelligence",
    "lookup_exploitdb_cves",
    "lookup_kev_cves",
]
