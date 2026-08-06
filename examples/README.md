# VulnMind Examples

Quick examples for common scanner outputs.

## nmap XML

```bash
nmap -sV -sC -oX scan.xml 192.168.1.10
vulnmind analyze scan.xml
vulnmind analyze scan.xml --format json > findings.json
```

## Nuclei JSONL

```bash
nuclei -u https://target.local -jsonl -o nuclei.jsonl
vulnmind analyze nuclei.jsonl --deep --format json
```

Expected JSON shape:

```json
[
  {
    "source_tool": "nuclei",
    "host": "target.local",
    "port": 443,
    "service": "http",
    "title": "Apache Path Traversal and File Disclosure",
    "cve_ids": ["CVE-2021-41773"],
    "priority": "critical",
    "confidence": "scanner-reported",
    "actively_exploited": true,
    "exploit_available": true,
    "metasploit_available": true,
    "exploit_confidence": "cisa-kev",
    "exploit_references": [
      "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
      "https://www.exploit-db.com/exploits/50383",
      "metasploit:exploit/multi/http/apache_normalize_path_rce"
    ]
  }
]
```

The booleans distinguish different claims: CISA KEV means the associated CVE
is known to be exploited in the wild; an ExploitDB reference means public
exploit material exists; neither field alone proves this target is vulnerable.

## Multiple Inputs

```bash
vulnmind analyze scan.xml nuclei.jsonl nikto.txt metasploit.log --deep
```

`--deep` refreshes NVD, CISA KEV, and ExploitDB data. Without it, finding
enrichment stays offline and uses existing caches plus the built-in knowledge
base; normal text output may separately perform the documented release check.
