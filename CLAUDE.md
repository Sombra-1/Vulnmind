# VulnMind — Project Context for Claude

## What this is

VulnMind is a CLI security scan analyzer for Linux (Kali, Ubuntu, Arch, Parrot, BlackArch).
Users run nmap/nikto normally, then run `vulnmind analyze scan.xml` to get structured findings,
CVE matches, priority ratings, suggested commands, and Metasploit modules.

The tool does NOT market itself as an AI tool. It is a security analyzer that optionally
supports deep enrichment via `--enrich` flag.

## Project location

```
/home/ayx/projects/vulnmind/
```

Virtualenv: `.venv/` — always use `.venv/bin/python` and `.venv/bin/vulnmind`

## Architecture

```
vulnmind/
├── parsers/
│   ├── base.py         Finding dataclass + BaseParser ABC
│   ├── __init__.py     Auto-detector (content-signature based) + load_files()
│   ├── nmap.py         nmap XML (ElementTree) + text (regex state machine)
│   └── nikto.py        nikto text (state machine: header -> findings)
├── knowledge/
│   └── services.json   Offline CVE/vuln database (services, versions, priorities)
├── matcher.py          Matches findings against services.json — always runs, offline
├── ai.py               Groq API enrichment (optional, --enrich flag only)
├── license.py          HMAC-SHA256 offline Pro key validation + freemium gate
├── config.py           ~/.vulnmind/config.json — API key, license key
├── cli.py              Click commands + Rich terminal display
└── report.py           ReportLab PDF generation (Pro only)
tools/
└── generate_key.py     Admin script to generate Pro license keys (not shipped)
tests/
├── sample_nmap.xml     Sample nmap XML with real vulnerabilities
├── sample_nmap.txt     Sample nmap text output
└── sample_nikto.txt    Sample nikto output
```

## Data flow

```
scan file(s)
    -> load_files()         parse into List[Finding]
    -> match_findings()     enrich from knowledge base (offline, always)
    -> partition_findings() split into (free, locked) based on license tier
    -> enrich_findings()    Groq API enrichment (only if --enrich flag used)
    -> display_results()    Rich terminal output
    -> generate_pdf()       ReportLab PDF (Pro + --report pdf only)
```

The `Finding` dataclass in `parsers/base.py` is the universal data structure.
Every module speaks Finding objects. Never pass raw strings between modules.

## CLI usage

```bash
vulnmind analyze scan.xml                    # offline, instant, no setup
vulnmind analyze scan.xml nikto.txt          # multi-file, auto-deduplication
vulnmind analyze scan.xml --enrich           # deep analysis via Groq API
vulnmind analyze scan.xml --enrich --report pdf   # PDF report (Pro)
vulnmind config set-key gsk_...              # save Groq API key
vulnmind config set-license <key>           # activate Pro license
vulnmind config show                         # show current config
```

## Key design decisions

- **No AI branding** — output never says "AI", "powered by", or mentions Groq
- **Offline first** — matcher.py + knowledge base runs on every scan, no key needed
- **--enrich is opt-in** — deep analysis only when explicitly requested
- **Content-signature detection** — parser auto-detection reads first 200 bytes, never trusts file extensions
- **Finding.id deduplication** — sha256(host+port+title)[:12] prevents duplicate findings from nmap -oA
- **HMAC license keys** — offline validation, works air-gapped, no license server
- **Freemium gate** — free tier shows the highest-priority finding as teaser, rest locked
- **Non-fatal AI failures** — if Groq is down, show raw findings, never crash
- **safe_text() in report.py** — must sanitize &, <, > before any ReportLab Paragraph

## Adding a new parser

1. Create `vulnmind/parsers/yourparser.py`, subclass `BaseParser`
2. Implement `can_parse(path, content_preview)` and `parse(path, content)`
3. Register in `vulnmind/parsers/__init__.py` → `REGISTERED_PARSERS` list

## Adding knowledge base entries

Edit `vulnmind/knowledge/services.json`. Entry format:
```json
{
  "service_name": [
    {
      "product": "product name or null",
      "version_match": "exact version or null",
      "version_before": "max vulnerable version or null",
      "priority": "critical|high|medium|low",
      "cves": ["CVE-YYYY-NNNN"],
      "description": "plain English description",
      "suggested_commands": ["command with {host} and {port} placeholders"],
      "metasploit_modules": ["exact/module/path"]
    }
  ]
}
```

## Generating Pro license keys

```bash
cd /home/ayx/projects/vulnmind
.venv/bin/python tools/generate_key.py
```

## Style rules

- No emojis anywhere in terminal output
- No "AI" language in any user-facing text
- Rich for all terminal output — no plain print() calls
- Errors must be helpful and specific, never cryptic
- Non-fatal failures: warn with Rich panel, continue with partial results
- Use `dataclasses.replace()` to update Finding objects — never mutate in place

## What's next (planned)

- Metasploit output parser
- NVD CVE lookup for --enrich --deep mode
- Ollama support (local LLM alternative to Groq)
- AUR package / Kali .deb
- More entries in services.json (more services, more versions)
