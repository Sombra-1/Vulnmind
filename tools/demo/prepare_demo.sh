#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

test -x .venv/bin/python || python -m venv .venv
.venv/bin/pip install -e .
mkdir -p output
.venv/bin/vulnmind analyze tools/demo/fixtures/sanitized-nmap.txt \
  tools/demo/fixtures/sanitized-metasploit.txt
