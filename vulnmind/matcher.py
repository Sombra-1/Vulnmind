"""
matcher.py — Offline knowledge base matcher.

Enriches Finding objects using a built-in database of known vulnerable
services, versions, and CVEs. No API, no internet, no AI — instant.

How it works:
  1. Takes a Finding with host, port, service, and description
  2. Looks up the service name in services.json
  3. Matches the product and version against known vulnerable entries
  4. Returns the Finding enriched with priority, CVEs, commands, modules

Matching logic (in order of specificity):
  1. Exact version match   — e.g. vsftpd 2.3.4 exactly
  2. Version before X      — e.g. OpenSSH < 8.0
  3. Product only          — e.g. any TP-LINK device
  4. Service fallback      — e.g. any HTTP server

Version comparison:
  Versions like "2.4.49", "7.2p2", "2012.55" are normalised to numeric
  tuples for comparison. Non-numeric parts are stripped.
"""

import json
import re
from dataclasses import replace
from pathlib import Path

_KNOWLEDGE_FILE = Path(__file__).parent / "knowledge" / "services.json"
_knowledge: dict | None = None


def _load_knowledge() -> dict:
    global _knowledge
    if _knowledge is None:
        with open(_KNOWLEDGE_FILE) as f:
            _knowledge = json.load(f)
    return _knowledge


def match_finding(finding) -> object:
    """
    Enrich a Finding from the offline knowledge base.

    Returns an enriched copy of the finding, or the original if no match.
    """
    knowledge = _load_knowledge()

    service = (finding.service or "").lower().strip()
    if not service:
        return finding

    # Normalise service aliases
    service = _normalise_service(service)

    entries = knowledge.get(service)
    if not entries:
        return finding

    # Extract product and version from the finding description/title
    product, version = _extract_product_version(finding)

    # Find the best matching entry
    match = _find_best_match(entries, product, version)
    if not match:
        return finding

    # Merge CVEs — keep any already found by the parser
    existing_cves = set(finding.cve_ids or [])
    new_cves = set(match.get("cves", []))
    merged_cves = list(existing_cves | new_cves)

    # Build commands with host/port substituted in
    host = finding.host
    port = str(finding.port) if finding.port else ""
    commands = [
        cmd.replace("{host}", host).replace("{port}", port)
        for cmd in match.get("suggested_commands", [])
    ]

    matched_priority = match.get("priority")
    kb_priority_reason = match.get("priority_reason") or (
        f"Matched offline KB entry for '{match.get('product') or service}' — "
        f"known vulnerable service with {len(merged_cves)} associated CVE(s)."
        if merged_cves else
        f"Matched offline KB entry for '{match.get('product') or service}'."
    )

    return replace(
        finding,
        priority=finding.priority or matched_priority,
        priority_reason=finding.priority_reason or kb_priority_reason,
        cve_ids=merged_cves,
        description=match.get("description") or finding.description,
        suggested_commands=finding.suggested_commands or commands,
        metasploit_modules=finding.metasploit_modules or match.get("metasploit_modules", []),
        false_positive_likelihood=finding.false_positive_likelihood or "low",
        false_positive_reason=finding.false_positive_reason or "Matched against known vulnerable service signature in offline knowledge base.",
        remediation=finding.remediation or match.get("remediation"),
    )


def match_findings(findings: list) -> list:
    """Enrich a list of findings from the knowledge base."""
    return [match_finding(f) for f in findings]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _normalise_service(service: str) -> str:
    """Map service name variations to the key used in services.json."""
    aliases = {
        # SSH
        "ssh":              "ssh",
        "ssh-hostkey":      "ssh",
        # FTP
        "ftp":              "ftp",
        "ftp-data":         "ftp",
        "ftps":             "ftp",
        "sftp":             "ftp",
        # HTTP / HTTPS
        "http":             "http",
        "http-proxy":       "http",
        "https":            "http",
        "ssl/http":         "http",
        "http-alt":         "http",
        "https-alt":        "http",
        "http-mgmt":        "http",
        "ssl/https":        "http",
        "http?":            "http",
        # UPnP / SSDP
        "upnp":             "upnp",
        "ssdp":             "upnp",
        # SMB / NetBIOS / Samba
        "microsoft-ds":     "microsoft-ds",
        "netbios-ssn":      "microsoft-ds",
        "smb":              "microsoft-ds",
        "samba":            "microsoft-ds",
        "netbios-ns":       "microsoft-ds",
        "cifs":             "microsoft-ds",
        # DNS
        "domain":           "domain",
        "dns":              "domain",
        "mdns":             "domain",
        # Telnet
        "telnet":           "telnet",
        # RDP
        "ms-wbt-server":    "rdp",
        "rdp":              "rdp",
        # Databases
        "mysql":            "mysql",
        "mariadb":          "mysql",
        "redis":            "redis",
        "mongodb":          "mongodb",
        "mongod":           "mongodb",
        "mongodb-internal": "mongodb",
        "postgresql":       "postgresql",
        "postgres":         "postgresql",
        "ms-sql-s":         "mssql",
        "ms-sql-m":         "mssql",
        "mssql":            "mssql",
        "oracle":           "oracle",
        "oracle-tns":       "oracle",
        "cassandra":        "cassandra",
        "cql":              "cassandra",
        "elasticsearch":    "elasticsearch",
        "memcached":        "memcached",
        # Application servers
        "tomcat":           "tomcat",
        "http-tomcat":      "tomcat",
        "ajp13":            "tomcat",
        "weblogic":         "weblogic",
        "jboss":            "jboss",
        "jboss-remoting":   "jboss",
        "docker":           "docker",
        # SMTP / Mail
        "smtp":             "smtp",
        "smtps":            "smtp",
        "smtp-submission":  "smtp",
        "submission":       "smtp",
        # IMAP / POP3
        "imap":             "imap",
        "imaps":            "imap",
        "pop3":             "pop3",
        "pop3s":            "pop3",
        # SNMP
        "snmp":             "snmp",
        # LDAP
        "ldap":             "ldap",
        "ldaps":            "ldap",
        "msrpc":            "rpc",
        # VNC
        "vnc":              "vnc",
        "rfb":              "vnc",
        "vnc-http":         "vnc",
        # NFS / RPC
        "nfs":              "nfs",
        "sunrpc":           "rpc",
        "rpcbind":          "rpc",
        # Kubernetes / CI
        "kubernetes":       "kubernetes",
        "jenkins":          "jenkins",
        "kafka":            "kafka",
        "rabbitmq":         "rabbitmq",
        "amqp":             "rabbitmq",
        "zookeeper":        "zookeeper",
    }
    return aliases.get(service, service)


def _extract_product_version(finding) -> tuple:
    """
    Extract product name and version string from a finding.

    Looks in: title, description, raw_evidence
    Returns: (product_str, version_str) — both lowercase, may be empty string

    Version extraction searches AFTER the matched product name to avoid
    picking up port numbers or other numeric values that appear before it.
    """
    text = " ".join([
        finding.title or "",
        finding.description or "",
        finding.raw_evidence or "",
    ]).lower()

    product = ""
    version = ""
    product_end = 0  # character position after product match — search version after this

    # Product detection patterns — ordered: specific before generic
    product_patterns = [
        # SSH
        (r"dropbear",               "dropbear"),
        (r"openssh",                "openssh"),
        # FTP
        (r"vsftpd",                 "vsftpd"),
        (r"proftpd",                "proftpd"),
        (r"pure-ftpd",              "pure-ftpd"),
        (r"filezilla\s+server",     "filezilla"),
        # HTTP servers
        (r"apache\s+httpd",         "apache"),
        (r"apache",                 "apache"),
        (r"nginx",                  "nginx"),
        (r"microsoft.iis",          "iis"),
        (r"\biis\b",                "iis"),
        (r"lighttpd",               "lighttpd"),
        (r"caddy",                  "caddy"),
        # Application servers
        (r"apache\s+tomcat",        "tomcat"),
        (r"tomcat",                 "tomcat"),
        (r"weblogic",               "weblogic"),
        (r"jboss",                  "jboss"),
        (r"wildfly",                "jboss"),
        (r"glassfish",              "glassfish"),
        (r"jetty",                  "jetty"),
        # CMS / frameworks
        (r"wordpress",              "wordpress"),
        (r"wp[\s/-]",               "wordpress"),
        (r"drupal",                 "drupal"),
        (r"joomla",                 "joomla"),
        (r"struts",                 "struts"),
        (r"spring\s+boot",          "spring"),
        (r"laravel",                "laravel"),
        (r"django",                 "django"),
        # Databases
        (r"mysql",                  "mysql"),
        (r"mariadb",                "mysql"),
        (r"postgresql",             "postgresql"),
        (r"microsoft\s+sql\s+server", "mssql"),
        (r"mssql",                  "mssql"),
        (r"redis",                  "redis"),
        (r"mongodb",                "mongodb"),
        (r"oracle",                 "oracle"),
        (r"cassandra",              "cassandra"),
        (r"elasticsearch",          "elasticsearch"),
        (r"memcached",              "memcached"),
        # Network devices
        (r"tp.?link",               "tp-link"),
        (r"cisco\s+ios",            "cisco"),
        (r"cisco",                  "cisco"),
        (r"juniper",                "juniper"),
        (r"fortinet",               "fortinet"),
        (r"palo\s+alto",            "palo-alto"),
        (r"netgear",                "netgear"),
        (r"ubiquiti",               "ubiquiti"),
        # UPnP / SSDP
        (r"portable sdk.*upnp",     "portable sdk for upnp"),
        (r"miniupnp",               "miniupnp"),
        # Samba / SMB
        (r"samba",                  "samba"),
        # Docker / Kubernetes
        (r"docker",                 "docker"),
        (r"kubernetes",             "kubernetes"),
        # Mail
        (r"postfix",                "postfix"),
        (r"exim",                   "exim"),
        (r"sendmail",               "sendmail"),
        (r"dovecot",                "dovecot"),
        # CI / DevOps
        (r"jenkins",                "jenkins"),
        (r"gitlab",                 "gitlab"),
        # Other
        (r"openssl",                "openssl"),
        (r"php",                    "php"),
        (r"python",                 "python"),
        (r"ruby",                   "ruby"),
        (r"node",                   "nodejs"),
        (r"vnc",                    "vnc"),
    ]

    for pattern, name in product_patterns:
        m = re.search(pattern, text)
        if m:
            product = name
            product_end = m.end()
            break

    # Version extraction — search AFTER the product match to avoid grabbing
    # port numbers or other numerics that appear before the product name.
    search_from = product_end if product_end else 0
    version_match = re.search(
        r"\b(\d+[\.\d]*(?:p\d+)?(?:[-_]\w+)?)\b",
        text[search_from:],
    )
    if version_match:
        candidate = version_match.group(1)
        # Reject bare single integers (likely port numbers or counts)
        if "." in candidate or re.search(r"p\d+", candidate):
            version = candidate

    return product, version


def _find_best_match(entries: list, product: str, version: str) -> dict | None:
    """
    Find the best matching entry from the knowledge base.

    Priority order:
      1. Exact version match for the detected product
      2. Version-before match for the detected product
      3. Product-only match (no version constraint)
      4. Service-level fallback (product=None entry)
    """
    fallback = None

    for entry in entries:
        entry_product = (entry.get("product") or "").lower()
        version_match = entry.get("version_match")
        version_before = entry.get("version_before")

        # Track the fallback (entry with no product constraint)
        if not entry_product:
            if fallback is None:
                fallback = entry
            continue

        # Skip if product doesn't match
        if product and entry_product and entry_product not in product and product not in entry_product:
            continue

        # Exact version match
        if version_match and version:
            if version.startswith(version_match):
                return entry

        # Version-before match
        if version_before and version:
            if _version_less_than(version, version_before):
                return entry

        # Product matched, no version constraint
        if not version_match and not version_before:
            return entry

    return fallback


def _version_less_than(v1: str, v2: str) -> bool:
    """
    Return True if version v1 is less than v2.

    Handles versions like: "7.2p2", "2012.55", "2.4.49", "1.6.19"
    Non-numeric parts (like 'p2') are stripped for comparison.
    """
    def normalise(v: str) -> tuple:
        # Extract only numeric parts separated by dots
        parts = re.findall(r"\d+", v)
        return tuple(int(p) for p in parts)

    try:
        return normalise(v1) < normalise(v2)
    except (ValueError, TypeError):
        return False
