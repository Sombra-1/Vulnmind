# Reproducing the VulnMind launch media

The demo uses committed, sanitized scanner-output fixtures only. It does not
run a scanner or contact a target. The rendered findings come from the real
VulnMind CLI and offline knowledge base.

## Dependencies

- Python 3.10+ and VulnMind's declared Python dependencies
- FFmpeg/FFprobe
- ImageMagick
- Poppler (`pdftoppm`, `pdfinfo`)
- Noto Sans and Noto Sans Mono fonts

## Render

```bash
tools/demo/prepare_demo.sh
tools/demo/render_assets.sh
tools/demo/record_github_demo.sh
tools/demo/verify_media.sh
```

The first command installs VulnMind into `.venv`. Rendering writes repository
images to `docs/assets/` and local video deliverables to ignored `output/`.

`--enrich` and `--deep` are intentionally absent from the deterministic
recording: Groq, NVD, CISA KEV, and ExploitDB refreshes require network access.
The media uses offline parsing and matching while accurately listing the
implemented Nmap, Nuclei, Nikto, Metasploit, JSON, PDF, confidence, CVSS, KEV,
and exploit-intelligence capabilities.
