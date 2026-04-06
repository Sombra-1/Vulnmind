"""
parsers/base.py — The spine of VulnMind.

Every scanner output (nmap, nikto, etc.) gets converted into Finding objects.
Every downstream module (AI, display, PDF) reads from Finding objects.
Nothing speaks directly to raw scanner output after the parser runs.

Two things live here:
  1. Finding — the data structure (dataclass)
  2. BaseParser — the interface every parser must implement (ABC)
"""

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Finding — the universal data structure
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """
    One vulnerability or noteworthy observation from a scanner.

    Fields are grouped by when they get populated:

      Parser fields    — set by nmap.py / nikto.py at parse time
      Enrichment       — set by ai.py after the Groq API call
      Metadata         — set at creation time, never mutated
    """

    # --- Metadata (set at creation, never changed) ---

    id: str
    """Short hash: sha256(host + port + title)[:12]. Used for deduplication.
    If nmap -oA produces scan.xml AND scan.nmap, both produce the same Finding id
    so we skip the duplicate when building the results list."""

    source_tool: str
    """Which tool produced this: 'nmap', 'nikto', 'metasploit'"""

    source_file: str
    """Absolute path to the file this came from"""

    timestamp: str
    """ISO-8601 UTC timestamp of when VulnMind parsed this finding"""

    # --- Target info (set by parser) ---

    host: str
    """IP address or hostname of the target"""

    port: Optional[int]
    """Port number, or None if not applicable (e.g. a host-level finding)"""

    protocol: Optional[str]
    """'tcp' or 'udp', or None"""

    service: Optional[str]
    """Service name: 'http', 'ssh', 'smb', etc."""

    # --- Vulnerability info (set by parser) ---

    title: str
    """Human-readable name for this finding. Keep it short.
    Example: 'SSH version outdated (OpenSSH 7.2)', 'SMB signing disabled'"""

    description: str
    """Cleaned, summarised description. Not the raw tool output."""

    raw_evidence: str
    """Verbatim snippet from the scanner output. This is what gets sent to
    the AI — it provides the full context the LLM needs to reason accurately."""

    # --- CVE info (populated by parser regex + optional NVD lookup) ---

    cve_ids: list = field(default_factory=list)
    """List of CVE IDs found in the raw output: ['CVE-2021-44228', ...]
    Populated by scanning raw_evidence for CVE-YYYY-NNNN patterns."""

    cvss_score: Optional[float] = None
    """CVSS v3 base score (0.0 - 10.0). Populated via NVD lookup (--deep mode)."""

    # --- Priority (set after AI enrichment or rule-based fallback) ---

    priority: Optional[str] = None
    """'critical', 'high', 'medium', or 'low'.
    Set by the AI response, or derived from CVSS score as a fallback."""

    # --- AI enrichment fields (set by ai.py, None until enriched) ---

    ai_explanation: Optional[str] = None
    """2-3 sentence plain-English explanation of what this vulnerability means
    and why it matters. Written for a pentester, not a developer."""

    suggested_commands: list = field(default_factory=list)
    """Exact shell commands to verify or exploit this finding.
    Example: ['curl -s http://192.168.1.1/admin/', 'hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.1']"""

    metasploit_modules: list = field(default_factory=list)
    """Exact Metasploit module paths.
    Example: ['exploit/unix/ftp/vsftpd_234_backdoor', 'auxiliary/scanner/smb/smb_ms17_010']"""

    false_positive_likelihood: Optional[str] = None
    """'low', 'medium', or 'high'. AI assessment of whether this is a real finding."""

    false_positive_reason: Optional[str] = None
    """AI explanation for the false_positive_likelihood rating."""


def make_finding_id(host: str, port: Optional[int], title: str) -> str:
    """Generate a short, deterministic ID for a finding.

    Why deterministic? So that the same finding discovered by two different
    tools (or nmap -oA producing multiple output formats) produces the same ID,
    allowing deduplication.

    Why only 12 chars? Long enough to be unique across any realistic scan,
    short enough to display in a table column.
    """
    raw = f"{host}{port}{title}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def make_timestamp() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# BaseParser — the interface every parser must implement
# ---------------------------------------------------------------------------

class BaseParser(ABC):
    """
    Abstract base class for all VulnMind parsers.

    How the auto-detection system works:
      1. parsers/__init__.py maintains a list of all registered parsers
      2. When the user passes a file, the auto-detector reads the first 200 bytes
      3. It calls can_parse() on each registered parser
      4. The first parser that returns True gets to parse the whole file
      5. The parser returns a List[Finding]

    Adding a new tool (e.g. OpenVAS):
      - Create vulnmind/parsers/openvas.py
      - Subclass BaseParser
      - Implement can_parse() and parse()
      - Register it in parsers/__init__.py
      That's it. Nothing else needs to change.
    """

    @abstractmethod
    def can_parse(self, file_path: Path, content_preview: str) -> bool:
        """
        Return True if this parser can handle the given file.

        Args:
            file_path: Path to the file (use for extension hints if needed)
            content_preview: First 200 bytes of the file as a string.
                             Use this for content-signature detection.
                             Do NOT rely on file_path.suffix alone — users
                             rename files and extensions are unreliable on Kali.
        """
        ...

    @abstractmethod
    def parse(self, file_path: Path, content: str) -> list:
        """
        Parse the full file content and return a list of Finding objects.

        Args:
            file_path: Path to the file (for source_file field on findings)
            content: Full file content as a string

        Returns:
            List[Finding] — may be empty if the file had no useful findings.
            Never raise an exception for malformed input; log a warning and
            return whatever findings were successfully parsed.
        """
        ...


# ---------------------------------------------------------------------------
# ParseError — raised when no parser can handle a file
# ---------------------------------------------------------------------------

class ParseError(Exception):
    """
    Raised when no registered parser recognises the file format.

    The message should always be helpful:
      "Could not detect file format for 'scan.txt'.
       Supported formats: nmap XML (-oX), nmap text (-oN), Nikto text output.
       Tip: run nmap with -oX to get reliable XML output."
    """
    pass
