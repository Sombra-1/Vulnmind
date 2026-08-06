#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
trap 'rm -f vulnmind_report.pdf' EXIT

.venv/bin/pytest -q
.venv/bin/vulnmind analyze tools/demo/fixtures/sanitized-nmap.txt --report pdf >/dev/null
pdfinfo vulnmind_report.pdf | grep -q '^Pages:'

test "$(ffprobe -v error -select_streams v:0 -show_entries stream=width,height -of csv=s=x:p=0 output/vulnmind-github-demo.mp4)" = "1920x1080"
test "$(ffprobe -v error -select_streams v:0 -show_entries stream=width,height -of csv=s=x:p=0 output/vulnmind-linkedin-1080x1350.mp4)" = "1080x1350"
test "$(ffprobe -v error -select_streams v:0 -show_entries stream=codec_name -of csv=p=0 output/vulnmind-github-demo.mp4)" = "h264"
test "$(ffprobe -v error -select_streams v:0 -show_entries stream=codec_name -of csv=p=0 output/vulnmind-linkedin-1080x1350.mp4)" = "h264"

if grep -R -E '/home/|api[_-]?key|gsk_|Sombra-1@|hostname=' docs/assets output --exclude='*.mp4' --exclude='*.gif'; then
  echo "Sensitive text found" >&2
  exit 1
fi

echo "Media verification passed."
