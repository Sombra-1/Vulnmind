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
vulnmind analyze nuclei.jsonl
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
    "priority": "critical"
  }
]
```

## Multiple Inputs

```bash
vulnmind analyze scan.xml nuclei.jsonl nikto.txt metasploit.log --deep
```
