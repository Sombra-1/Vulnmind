#!/usr/bin/env python3
"""Render VulnMind's deterministic launch assets with Pillow and FFmpeg."""

from __future__ import annotations

import os
import shutil
import subprocess
import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont

ROOT = Path(__file__).resolve().parents[2]
ASSETS = ROOT / "docs" / "assets"
OUTPUT = ROOT / "output"
WORK = OUTPUT / "media-work"
FIXTURE = ROOT / "tools" / "demo" / "fixtures" / "sanitized-nmap.txt"
MSF_FIXTURE = ROOT / "tools" / "demo" / "fixtures" / "sanitized-metasploit.txt"
CLI = ROOT / ".venv" / "bin" / "vulnmind"
SANS = "/usr/share/fonts/noto/NotoSans-Regular.ttf"
BOLD = "/usr/share/fonts/noto/NotoSans-Bold.ttf"
MONO = "/usr/share/fonts/noto/NotoSansMono-Regular.ttf"

BG = "#07111f"
PANEL = "#101f32"
MUTED = "#94a8bf"
TEXT = "#edf7ff"
CYAN = "#50e3c2"
RED = "#ff5d6c"
ORANGE = "#ffad5a"


def font(path: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(path, size)


def canvas(size: tuple[int, int]) -> Image.Image:
    image = Image.new("RGB", size, BG)
    draw = ImageDraw.Draw(image)
    w, h = size
    for x in range(0, w, max(60, w // 18)):
        draw.line((x, 0, x, h), fill="#0b1828", width=1)
    for y in range(0, h, max(60, h // 14)):
        draw.line((0, y, w, y), fill="#0b1828", width=1)
    draw.ellipse((w * .58, -h * .35, w * 1.1, h * .55), fill="#0d2634")
    return image.filter(ImageFilter.GaussianBlur(0.3))


def fit_lines(text: str, width: int, face: ImageFont.FreeTypeFont) -> list[str]:
    draw = ImageDraw.Draw(Image.new("RGB", (10, 10)))
    lines: list[str] = []
    for paragraph in text.splitlines() or [""]:
        if not paragraph:
            lines.append("")
            continue
        words = paragraph.split(" ")
        line = ""
        for word in words:
            trial = f"{line} {word}".strip()
            if draw.textlength(trial, font=face) <= width:
                line = trial
            else:
                if line:
                    lines.append(line)
                line = word
        lines.append(line)
    return lines


def centered(draw: ImageDraw.ImageDraw, xy: tuple[int, int], text: str, face, fill=TEXT):
    box = draw.multiline_textbbox((0, 0), text, font=face, spacing=10, align="center")
    draw.multiline_text((xy[0] - (box[2] - box[0]) / 2, xy[1]), text,
                        font=face, fill=fill, spacing=10, align="center")


def brand(draw: ImageDraw.ImageDraw, w: int, y: int = 44, scale: float = 1):
    draw.rounded_rectangle((56, y, 72, y + 54 * scale), radius=7, fill=CYAN)
    draw.text((92, y - 4), "VulnMind", font=font(BOLD, int(42 * scale)), fill=TEXT)
    draw.text((w - 290 * scale, y + 9), "OFFLINE-FIRST", font=font(BOLD, int(19 * scale)), fill=CYAN)


def card(size, title, subtitle="", eyebrow="", body=None, accent=CYAN) -> Image.Image:
    image = canvas(size)
    draw = ImageDraw.Draw(image)
    w, h = size
    brand(draw, w, int(h * .045), min(w / 1600, h / 900))
    top = int(h * .22)
    if eyebrow:
        eyebrow_face = font(BOLD, max(int(h * .025), int(w * .012)))
        eyebrow_lines = "\n".join(fit_lines(eyebrow.upper(), int(w * .82), eyebrow_face))
        centered(draw, (w // 2, top), eyebrow_lines, eyebrow_face, accent)
        eyebrow_height = draw.multiline_textbbox(
            (0, 0), eyebrow_lines, font=eyebrow_face, spacing=10
        )[3]
        top += eyebrow_height + int(h * .035)
    title_face = font(BOLD, max(
        int(h * (.062 if w / h > 1.2 else .052)),
        int(w * .04),
    ))
    title_lines = "\n".join(fit_lines(title, int(w * .78), title_face))
    centered(draw, (w // 2, top), title_lines, title_face)
    title_h = draw.multiline_textbbox((0, 0), title_lines, font=title_face, spacing=10)[3]
    y = top + title_h + int(h * .045)
    if subtitle:
        sub_face = font(SANS, max(int(h * .03), int(w * .018)))
        centered(draw, (w // 2, y), "\n".join(fit_lines(subtitle, int(w * .76), sub_face)), sub_face, MUTED)
        y += int(h * .12)
    if body:
        box = (int(w * .1), y, int(w * .9), int(h * .86))
        draw.rounded_rectangle(box, radius=24, fill=PANEL, outline="#29415e", width=2)
        body_face = font(MONO, int(h * (.024 if w / h > 1.2 else .022)))
        draw.multiline_text((box[0] + int(w * .035), box[1] + int(h * .035)),
                            "\n".join(body), font=body_face, fill=TEXT,
                            spacing=int(h * .013))
    return image


def terminal_image(size, output: str, command: str, start: str | None = None,
                   max_lines: int = 23) -> Image.Image:
    image = canvas(size)
    draw = ImageDraw.Draw(image)
    w, h = size
    margin = int(w * .055)
    box = (margin, int(h * .1), w - margin, int(h * .91))
    draw.rounded_rectangle(box, radius=24, fill="#08101b", outline="#29415e", width=3)
    draw.rounded_rectangle((box[0], box[1], box[2], box[1] + int(h * .07)),
                           radius=24, fill="#142338")
    for i, color in enumerate(("#ff5f57", "#febc2e", "#28c840")):
        draw.ellipse((box[0] + 24 + i * 34, box[1] + 20,
                      box[0] + 42 + i * 34, box[1] + 38), fill=color)
    mono = font(MONO, max(16, int(h * .0215)))
    y = box[1] + int(h * .095)
    draw.text((box[0] + 34, y), "$", font=mono, fill=CYAN)
    draw.text((box[0] + 62, y), command, font=mono, fill=TEXT)
    y += int(h * .054)
    lines = output.splitlines()
    if start:
        for index, line in enumerate(lines):
            if start in line:
                lines = lines[index:]
                break
    clean = [line.rstrip() for line in lines if line.strip()]
    for line in clean[:max_lines]:
        color = TEXT
        if "CRITICAL" in line:
            color = RED
        elif " HIGH " in line:
            color = ORANGE
        elif "CVEs:" in line or "Report saved:" in line:
            color = CYAN
        draw.text((box[0] + 34, y), line[:112], font=mono, fill=color)
        y += int(h * .0295)
    return image


def run_cli() -> tuple[str, str, Path]:
    env = os.environ | {"NO_COLOR": "1", "COLUMNS": "112"}
    command = [str(CLI), "analyze", str(FIXTURE), str(MSF_FIXTURE)]
    result = subprocess.run(command, cwd=ROOT, env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True)
    report = subprocess.run(
        [str(CLI), "analyze", str(FIXTURE), "--report", "pdf"],
        cwd=WORK, env=env, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, check=True,
    )
    return result.stdout, report.stdout, WORK / "vulnmind_report.pdf"


def save_pdf_preview(pdf: Path) -> Image.Image:
    prefix = WORK / "report-cover"
    subprocess.run(["pdftoppm", "-f", "1", "-singlefile", "-png", "-r", "150",
                    str(pdf), str(prefix)], check=True)
    page = Image.open(prefix.with_suffix(".png")).convert("RGB")
    image = canvas((1600, 900))
    page.thumbnail((640, 760), Image.Resampling.LANCZOS)
    image.paste(page, (880, 90))
    draw = ImageDraw.Draw(image)
    brand(draw, 1600)
    draw.text((100, 240), "A report built from\nreal findings.", font=font(BOLD, 58), fill=TEXT, spacing=14)
    draw.text((100, 410), "Executive summary\nFinding details\nTargets and priorities",
              font=font(SANS, 31), fill=MUTED, spacing=18)
    draw.rounded_rectangle((100, 610, 670, 684), radius=16, fill=PANEL, outline="#29415e")
    draw.text((132, 629), "$ vulnmind analyze scan.txt --report pdf",
              font=font(MONO, 22), fill=CYAN)
    return image


def write_concat(path: Path, frames: list[tuple[Path, int]]):
    rows = []
    for index, (frame, duration) in enumerate(frames):
        # The repeated final still makes FFmpeg apply its duration twice.
        effective_duration = duration / 2 if index == len(frames) - 1 else duration
        rows.extend((f"file '{frame.as_posix()}'", f"duration {effective_duration}"))
    rows.append(f"file '{frames[-1][0].as_posix()}'")
    path.write_text("\n".join(rows) + "\n")


def render_video(path: Path, frames: list[tuple[Path, int]]):
    concat = WORK / f"{path.stem}.txt"
    write_concat(concat, frames)
    subprocess.run([
        "ffmpeg", "-y", "-v", "error", "-f", "concat", "-safe", "0",
        "-i", str(concat), "-vf", "fps=30,format=yuv420p",
        "-c:v", "libx264", "-preset", "medium", "-crf", "18",
        "-movflags", "+faststart", str(path),
    ], check=True)


def write_support_files():
    (OUTPUT / "vulnmind-linkedin.srt").write_text("""1
00:00:00,000 --> 00:00:03,000
Your scanner found dozens of issues. Which one actually matters?

2
00:00:03,000 --> 00:00:13,000
VulnMind turns scanner output into prioritized security findings.

3
00:00:13,000 --> 00:00:28,000
Not just CVEs: target, evidence, context and priority.

4
00:00:28,000 --> 00:00:40,000
Nmap, Nikto and Metasploit. Terminal and PDF.

5
00:00:40,000 --> 00:00:52,000
Open source at github.com/Sombra-1/vulnmind
""")
    (OUTPUT / "vulnmind-linkedin-post.md").write_text("""I built VulnMind to make scanner output easier to act on.

It parses Nmap XML/text, Nikto text, and Metasploit console output, normalizes
the findings, and uses an offline knowledge base to add priority, CVE context,
suggested verification commands, and relevant Metasploit modules. The result
stays explainable: you can trace each finding back to the scanner evidence.

The default workflow is offline-first. Optional Groq enrichment is separate,
and the project does not present automated analysis as a replacement for
professional judgment.

VulnMind is open source: https://github.com/Sombra-1/vulnmind

Only test systems you own or are explicitly authorized to assess.

#OpenSource #CyberSecurity #AppSec #Pentesting
""")
    (OUTPUT / "vulnmind-video-script.md").write_text("""# VulnMind launch video script

## GitHub technical demo — 68 seconds

- 0–4s: Scanner signals become organized findings.
- 4–16s: Real sanitized Nmap XML and the real `vulnmind analyze` command.
- 16–30s: Critical Apache finding, target, CVEs, and priority.
- 30–42s: Offline knowledge context, suggested verification, Metasploit module.
- 42–54s: Real `--report pdf` command and generated report.
- 54–62s: Supported formats and the implemented analysis pipeline.
- 62–68s: Repository call to action.

## LinkedIn launch — 52 seconds

- 0–3s: Which scanner issue matters?
- 3–13s: Raw file to prioritized findings.
- 13–28s: Evidence, target, CVE context, and priority.
- 28–40s: Supported inputs and outputs, then PDF.
- 40–52s: Open-source closing card and repository URL.

No narration or music is included; every message is burned into the image.
""")
    (OUTPUT / "vulnmind-shot-list.md").write_text("""# Shot list

| Time | GitHub 16:9 | LinkedIn 4:5 |
|---|---|---|
| Hook | Raw sanitized scanner output | Re-composed large mobile hook |
| Analyze | Full-width real CLI capture | Tight command and result crop |
| Context | Critical finding + offline match | Large target/CVE/priority cards |
| Report | PDF cover beside command | Stacked mobile PDF composition |
| Close | Pipeline and repository | Inputs/outputs then owner statement |

All terminal material is generated from `tools/demo/fixtures/`. No target is
scanned during rendering.
""")


def main():
    ASSETS.mkdir(parents=True, exist_ok=True)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True, exist_ok=True)
    cli_output, report_output, pdf = run_cli()

    banner = card(
        (1600, 480), "VulnMind",
        "Turn scanner output into prioritized, explainable security findings.",
        "Open-source security scan analyzer",
    )
    banner.save(ASSETS / "vulnmind-banner.png", optimize=True)

    terminal = terminal_image(
        (1600, 900), cli_output,
        "vulnmind analyze sanitized-nmap.txt sanitized-metasploit.txt",
        start="╭", max_lines=24,
    )
    terminal.save(ASSETS / "terminal-analysis.png", optimize=True)

    intelligence = terminal_image(
        (1600, 900), cli_output,
        "vulnmind analyze sanitized-nmap.txt",
        start="CRITICAL", max_lines=23,
    )
    intelligence.save(ASSETS / "deep-intelligence.png", optimize=True)

    pdf_preview = save_pdf_preview(pdf)
    pdf_preview.save(ASSETS / "pdf-report-preview.png", optimize=True)

    thumbnail = card(
        (1280, 720), "Scanner output → decisions",
        "A verified VulnMind technical demo",
        "Nmap · Nikto · Metasploit",
        ["OFFLINE ANALYSIS", "PRIORITIZED FINDINGS", "CVE + REPORT CONTEXT"],
    )
    thumbnail.save(ASSETS / "video-thumbnail.png", optimize=True)

    raw = card(
        (1920, 1080), "Security scanners find signals.\nVulnMind turns them into decisions.",
        eyebrow="Raw output → organized findings",
        body=["<service product=\"Apache httpd\" version=\"2.4.49\"/>",
              "<script id=\"http-vuln-cve2021-41773\"",
              "        output=\"VULNERABLE ... CVE-2021-41773\"/>"],
    )
    analyze = terminal_image(
        (1920, 1080), cli_output, "vulnmind analyze sanitized-nmap.txt",
        start="╭", max_lines=20,
    )
    context = terminal_image(
        (1920, 1080), cli_output, "vulnmind analyze sanitized-nmap.txt",
        start="CRITICAL", max_lines=22,
    )
    report = pdf_preview.resize((1920, 1080), Image.Resampling.LANCZOS)
    pipeline = card(
        (1920, 1080), "One offline analysis pipeline.",
        "Content detection → parsing → normalization → knowledge matching → terminal / PDF",
        "Nmap XML + text · Nikto text · Metasploit console",
    )
    close = card(
        (1920, 1080), "Open source. Built for authorized testing.",
        "github.com/Sombra-1/vulnmind",
        "VulnMind",
    )
    github_scenes = [raw, analyze, context, context, report, pipeline, close]
    github_durations = [4, 12, 14, 12, 12, 8, 6]
    github_paths = []
    for index, scene in enumerate(github_scenes):
        path = WORK / f"github-{index}.png"
        scene.save(path)
        github_paths.append((path, github_durations[index]))
    render_video(OUTPUT / "vulnmind-github-demo.mp4", github_paths)

    li_raw = card(
        (1080, 1350), "Your scanner found dozens of issues.\nWhich one actually matters?",
        eyebrow="Raw scanner noise",
        body=["Apache httpd 2.4.49", "CVE-2021-41773", "MySQL 5.7.32"],
    )
    li_analyze = terminal_image(
        (1080, 1350), cli_output, "vulnmind analyze sanitized-nmap.txt",
        start="╭", max_lines=18,
    )
    li_context = card(
        (1080, 1350), "Not just CVEs.\nEvidence, context and priority.",
        "CRITICAL · demo.lab:80 · CVE-2021-41773",
        "Offline knowledge match",
        ["WHY IT MATTERS", "Apache 2.4.49 path traversal / RCE context",
         "", "NEXT STEP", "Version-specific verification command",
         "", "EXPLOIT CONTEXT", "Relevant Metasploit module path"],
        RED,
    )
    li_report = card(
        (1080, 1350), "Nmap · Nikto · Metasploit",
        "Terminal · PDF",
        "Supported today",
        ["$ vulnmind analyze sanitized-nmap.txt --report pdf",
         "", "REPORT SAVED", "vulnmind_report.pdf"],
    )
    li_close = card(
        (1080, 1350), "I built VulnMind to turn\nsecurity-scanner noise into decisions.",
        "Open source:\ngithub.com/Sombra-1/vulnmind",
        "Use only on systems you own or are authorized to assess",
    )
    li_scenes = [li_raw, li_analyze, li_context, li_report, li_close]
    li_durations = [3, 10, 15, 12, 12]
    li_paths = []
    for index, scene in enumerate(li_scenes):
        path = WORK / f"linkedin-{index}.png"
        scene.save(path)
        li_paths.append((path, li_durations[index]))
    render_video(OUTPUT / "vulnmind-linkedin-1080x1350.mp4", li_paths)

    gif_frames = [
        (WORK / "github-0.png", 3),
        (WORK / "github-1.png", 3),
        (WORK / "github-2.png", 3),
        (WORK / "github-4.png", 3),
        (WORK / "github-6.png", 3),
    ]
    gif_list = WORK / "gif.txt"
    write_concat(gif_list, gif_frames)
    subprocess.run([
        "ffmpeg", "-y", "-v", "error", "-f", "concat", "-safe", "0",
        "-i", str(gif_list),
        "-filter_complex",
        "fps=10,scale=960:540:flags=lanczos,split[a][b];"
        "[a]palettegen=max_colors=128[p];[b][p]paletteuse=dither=bayer",
        "-loop", "0", str(ASSETS / "vulnmind-demo.gif"),
    ], check=True)

    write_support_files()
    shutil.rmtree(WORK)
    print(f"Rendered assets in {ASSETS}")
    print(f"Rendered local deliverables in {OUTPUT}")


if __name__ == "__main__":
    main()
