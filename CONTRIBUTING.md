# Contributing to VulnMind

## What to contribute

The most valuable contributions are:

### 1. New parsers
Support for more tools: Metasploit, OpenVAS, Burp Suite, Nessus, Masscan, etc.

Create `vulnmind/parsers/toolname.py`:
```python
from vulnmind.parsers.base import BaseParser, Finding, make_finding_id, make_timestamp
from pathlib import Path

class ToolNameParser(BaseParser):
    def can_parse(self, file_path: Path, content_preview: str) -> bool:
        return "signature of this tool's output" in content_preview

    def parse(self, file_path: Path, content: str) -> list:
        findings = []
        # ... parse content into Finding objects
        return findings
```

Register it in `vulnmind/parsers/__init__.py`:
```python
from vulnmind.parsers.toolname import ToolNameParser
REGISTERED_PARSERS = [NmapParser(), NiktoParser(), ToolNameParser()]
```

### 2. Knowledge base entries
Add vulnerable service/version entries to `vulnmind/knowledge/services.json`.

Format:
```json
{
  "service_name": [
    {
      "product": "product name or null for any",
      "version_match": "exact version string or null",
      "version_before": "vulnerable if version < this, or null",
      "priority": "critical|high|medium|low",
      "cves": ["CVE-YYYY-NNNN"],
      "description": "Plain English. What is vulnerable and why it matters.",
      "suggested_commands": [
        "exact command with {host} and {port} placeholders"
      ],
      "metasploit_modules": ["exact/module/path"]
    }
  ]
}
```

Rules for knowledge base entries:
- CVE IDs must be real and verifiable
- Metasploit module paths must exist in a current Metasploit release
- Commands must be exact and runnable — no pseudocode
- Descriptions should be 1-2 sentences, plain English, no jargon

### 3. Bug reports
Open an issue with:
- Your distro and Python version
- The command you ran
- The error output
- A sample scan file if possible (sanitize IPs if needed)

## Development setup

```bash
git clone https://github.com/YOUR_USERNAME/vulnmind
cd vulnmind
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Testing your changes

```bash
# Test with included sample files
vulnmind analyze tests/sample_nmap.xml
vulnmind analyze tests/sample_nmap.txt
vulnmind analyze tests/sample_nikto.txt
vulnmind analyze tests/sample_nmap.xml tests/sample_nikto.txt
```

## Code style

- No emojis in terminal output
- No "AI" language in user-facing text
- All terminal output via Rich — no plain `print()`
- Finding objects are immutable — use `dataclasses.replace()` not mutation
- Error messages must be specific and helpful
