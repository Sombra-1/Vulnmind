#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

test -x .venv/bin/vulnmind || tools/demo/prepare_demo.sh
.venv/bin/python tools/demo/render_media.py
