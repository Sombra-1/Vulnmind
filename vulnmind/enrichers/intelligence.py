"""Apply exploit-intelligence lookups to normalized findings.

This layer owns policy while ``kev`` and ``exploitdb`` only own data access.
Exploit intelligence annotates findings; it never changes priority because a
public exploit or KEV entry does not prove that the scanned target is affected.
"""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Callable

from vulnmind.enrichers import exploitdb, kev

MAX_EXPLOIT_REFERENCES = 5
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,19}$", re.IGNORECASE)
_METASPLOIT_MODULE_RE = re.compile(
    r"^(?:exploit|auxiliary|post|payload|encoder|nop|evasion)/[\w./-]+$",
    re.IGNORECASE,
)


def enrich_with_exploit_intelligence(
    findings: list,
    *,
    allow_network: bool = False,
    kev_lookup: Callable = kev.lookup_cves,
    exploitdb_lookup: Callable = exploitdb.lookup_cves,
) -> list:
    """Return findings annotated with KEV, ExploitDB, and Metasploit signals.

    The CVE union is looked up once per source.  Callers should pass
    ``allow_network=True`` only for an explicit live-data mode such as
    ``--deep``; normal analysis consumes existing caches without networking.
    Any lookup failure is treated as no new data so reporting remains usable.
    """
    cve_ids = sorted({
        cve_id
        for finding in findings
        for cve_id in _normalized_cves(getattr(finding, "cve_ids", []))
    })

    kev_matches = _safe_lookup(kev_lookup, cve_ids, allow_network)
    exploitdb_matches = _safe_lookup(exploitdb_lookup, cve_ids, allow_network)

    enriched = []
    for finding in findings:
        finding_cves = _normalized_cves(getattr(finding, "cve_ids", []))
        finding_kev = [kev_matches[cve] for cve in finding_cves if cve in kev_matches]
        finding_exploits = [
            record
            for cve in finding_cves
            for record in _record_list(exploitdb_matches.get(cve))
        ]
        modules = _normalized_modules(
            getattr(finding, "metasploit_modules", [])
        )

        actively_exploited = bool(finding_kev)
        exploit_available = bool(finding_exploits)
        metasploit_available = bool(modules)

        if actively_exploited:
            exploit_confidence = "cisa-kev"
        elif metasploit_available:
            exploit_confidence = "metasploit-module"
        elif exploit_available:
            exploit_confidence = "exploitdb-cve"
        else:
            exploit_confidence = "none"

        references = []
        for record in finding_kev:
            if isinstance(record, dict):
                references.extend(_string_list(record.get("references", [])))
                references.extend(_string_list([record.get("source_url")]))
        exploit_urls = []
        for record in finding_exploits:
            if isinstance(record, dict):
                exploit_urls.extend(_string_list([record.get("url")]))
        module_ids = [f"metasploit:{module}" for module in modules]

        # Keep at least one reference for each true signal before filling the
        # remaining bounded slots. A long module list must not hide ExploitDB.
        if exploit_urls:
            references.append(exploit_urls[0])
        if module_ids:
            references.append(module_ids[0])
        references.extend(exploit_urls[1:])
        references.extend(module_ids[1:])

        enriched.append(replace(
            finding,
            actively_exploited=actively_exploited,
            exploit_available=exploit_available,
            metasploit_available=metasploit_available,
            exploit_confidence=exploit_confidence,
            exploit_references=_bounded_unique(references),
            metasploit_modules=modules,
        ))

    return enriched


def _safe_lookup(lookup: Callable, cve_ids: list[str], allow_network: bool) -> dict:
    if not cve_ids:
        return {}
    try:
        result = lookup(cve_ids, allow_network=allow_network)
    except Exception:
        return {}
    return result if isinstance(result, dict) else {}


def _normalized_cves(values) -> list[str]:
    normalized = []
    seen = set()
    if not isinstance(values, (list, tuple, set)):
        return normalized
    for value in values:
        if not isinstance(value, str):
            continue
        cve_id = value.strip().upper()
        if _CVE_RE.fullmatch(cve_id) and cve_id not in seen:
            seen.add(cve_id)
            normalized.append(cve_id)
    return normalized


def _record_list(value) -> list[dict]:
    if not isinstance(value, list):
        return []
    return [record for record in value if isinstance(record, dict)]


def _string_list(values) -> list[str]:
    if not isinstance(values, (list, tuple, set)):
        return []
    return [value.strip() for value in values if isinstance(value, str) and value.strip()]


def _normalized_modules(values) -> list[str]:
    """Keep only unique, runnable Metasploit module paths."""
    return _bounded_unique(
        value.strip()
        for value in values
        if isinstance(value, str) and _METASPLOIT_MODULE_RE.fullmatch(value.strip())
    )


def _bounded_unique(values) -> list[str]:
    result = []
    seen = set()
    for value in values:
        if not isinstance(value, str) or not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
        if len(result) >= MAX_EXPLOIT_REFERENCES:
            break
    return result
