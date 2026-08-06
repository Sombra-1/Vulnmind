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

`--enrich` is intentionally absent from the deterministic recording: it uses
the optional Groq integration and cannot be reproduced offline. VulnMind does
not currently implement Nuclei input, JSON output, CISA KEV lookup, official
CVSS lookup, or an evidence-confidence field, so the media makes none of those
claims.
