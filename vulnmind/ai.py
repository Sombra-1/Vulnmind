"""
ai.py — Groq API integration for AI-powered finding analysis.

What this module does:
  Takes a Finding object (from a parser) and sends it to Groq's API.
  The AI returns structured JSON with:
    - Plain-English explanation
    - Priority (critical/high/medium/low)
    - Exact commands to test/exploit the finding
    - Metasploit module paths
    - False positive assessment

Why Groq?
  - Free tier: 30 req/min, 14,400 req/day, no credit card
  - llama-3.1-8b-instant runs on Groq's LPU hardware — very fast
  - Good enough for structured security reasoning

Why temperature=0.3?
  Lower temperature = more deterministic, less creative.
  For security tooling, you want consistent, factual responses.
  A hallucinated Metasploit module path wastes a pentester's time.
  0.3 reduces hallucination while keeping responses useful.

The JSON problem:
  LLMs don't always obey "respond in JSON only." This module handles:
    - Markdown code fences (```json ... ```)
    - Preamble text before the JSON
    - Trailing text after the JSON
  If parsing still fails, we return the finding unenriched — never crash.

Rate limiting:
  Groq free tier = 30 req/min.
  We send at 25/min to stay safely under the limit.
  Progress is shown with a Rich progress bar.
"""

import json
import re
import time
from dataclasses import replace

import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from vulnmind.parsers.base import Finding

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_MODEL = "llama-3.3-70b-versatile"

# How many chars of raw_evidence to send in normal vs --deep mode
EVIDENCE_CHARS_NORMAL = 500
EVIDENCE_CHARS_DEEP = 1500

# Rate limiting: stay at 25/min to safely stay under Groq's 30/min limit
REQUESTS_PER_MINUTE = 25
DELAY_BETWEEN_REQUESTS = 60.0 / REQUESTS_PER_MINUTE  # 2.4 seconds

console = Console()


def enrich_findings(findings: list, cfg, deep: bool = False) -> list:
    """
    Enrich a list of findings with AI analysis.

    Sends each finding to the Groq API and returns enriched Finding objects.
    Uses a Rich progress bar if there are multiple findings.

    AI failures are non-fatal: if Groq is down or rate-limited, we return
    the original finding unchanged. The user still sees the raw parsed data.

    Args:
        findings: List of Finding objects to enrich
        cfg: Config object (for API key and model)
        deep: If True, send more evidence context to the AI

    Returns:
        List of Finding objects (enriched where possible, original on failure)
    """
    if not findings:
        return []

    api_key = cfg.groq_api_key
    model = cfg.model or DEFAULT_MODEL

    if len(findings) == 1:
        # Single finding — no progress bar, just enrich it
        return [_enrich_one(findings[0], api_key, model, deep)]

    # Multiple findings — show a progress bar
    enriched = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing findings...", total=len(findings))
        for i, finding in enumerate(findings):
            if i > 0:
                time.sleep(DELAY_BETWEEN_REQUESTS)
            progress.update(task, description=f"Analyzing {finding.host}:{finding.port}")
            enriched.append(_enrich_one(finding, api_key, model, deep))
            progress.advance(task)

    return enriched


def _enrich_one(finding: Finding, api_key: str, model: str, deep: bool) -> Finding:
    """
    Enrich a single finding with AI analysis.

    Returns the original finding unchanged if the API call fails.
    Never raises an exception.
    """
    try:
        prompt = _build_prompt(finding, deep)
        response_text = _call_groq(prompt, api_key, model)
        data = _parse_response(response_text)
        return _apply_enrichment(finding, data)
    except requests.exceptions.ConnectionError:
        console.print(
            f"[yellow]! Could not reach Groq API (no internet?). "
            f"Showing raw findings for {finding.host}:{finding.port}[/yellow]"
        )
        return finding
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            console.print("[red]! Invalid Groq API key. Run: vulnmind config set-key <key>[/red]")
        elif e.response.status_code == 429:
            console.print("[yellow]! Groq rate limit hit. Results may be partial.[/yellow]")
        else:
            console.print(f"[yellow]! Groq API error ({e.response.status_code}) for {finding.host}:{finding.port}[/yellow]")
        return finding
    except Exception:
        # Catch-all: parsing failures, timeouts, unexpected responses
        # Silently return unenriched rather than crashing the whole tool
        return finding


def _build_prompt(finding: Finding, deep: bool) -> str:
    """
    Build the prompt to send to the AI.

    The prompt asks for strict JSON output. We specify the exact fields and
    their allowed values. This reduces hallucination and makes parsing reliable.

    Why include raw_evidence?
      The AI needs to see exactly what the scanner reported to give accurate
      advice. A generic "open SSH port" prompt gets generic advice. A prompt
      that includes the actual NSE script output + CVE ID gets specific,
      actionable advice.

    The deep flag increases the amount of evidence we send.
    More context = better analysis, but longer prompts = more tokens = slower.
    """
    evidence_limit = EVIDENCE_CHARS_DEEP if deep else EVIDENCE_CHARS_NORMAL
    evidence = finding.raw_evidence[:evidence_limit]

    cve_str = ", ".join(finding.cve_ids) if finding.cve_ids else "none identified"
    port_str = str(finding.port) if finding.port else "N/A"
    service_str = finding.service or "unknown"

    prompt = f"""You are an expert penetration tester and security engineer analyzing a scan finding.
Analyze the finding below and respond with ONLY valid JSON — no markdown, no explanation outside the JSON.

Finding details:
- Scanner: {finding.source_tool}
- Host: {finding.host}
- Port: {port_str}/{finding.protocol or 'tcp'}
- Service: {service_str}
- Finding title: {finding.title}
- Description: {finding.description}
- Scanner evidence:
{evidence}
- CVE IDs: {cve_str}

Respond with this exact JSON structure (no other text):
{{
  "explanation": "2-4 sentence plain English explanation of what this vulnerability is, why it matters, and what an attacker can do with it",
  "priority": "critical|high|medium|low",
  "priority_reason": "one sentence explaining exactly why this severity was chosen — cite the specific risk factor (e.g. unauthenticated RCE, default credentials, data exposure)",
  "suggested_commands": [
    "exact shell command 1 targeting {finding.host}:{port_str}",
    "exact shell command 2 targeting {finding.host}:{port_str}",
    "exact shell command 3 for deeper enumeration or exploitation"
  ],
  "metasploit_modules": [
    "exact/module/path"
  ],
  "false_positive_likelihood": "low|medium|high",
  "false_positive_reason": "one sentence explaining false positive assessment — mention any conditions that could make this a non-issue",
  "remediation": "2-3 concrete, actionable fix steps — version to upgrade to, config change to make, service to disable, or firewall rule to add"
}}

Rules:
- suggested_commands must be exact, runnable shell commands. Use {finding.host} as the target IP.
- Include at least 2 commands: one to verify/confirm the issue, one to demonstrate impact
- metasploit_modules must be exact module paths (e.g. exploit/unix/ftp/vsftpd_234_backdoor)
- If no Metasploit module exists, use an empty array []
- remediation must be specific — not "patch the software" but "upgrade to version X.Y.Z" or "set AllowEmptyPasswords no in sshd_config"
- Do not include any text before or after the JSON object"""

    return prompt


def _call_groq(prompt: str, api_key: str, model: str) -> str:
    """
    Send prompt to Groq API and return the response text.

    Raises:
        requests.exceptions.HTTPError: on 4xx/5xx responses
        requests.exceptions.ConnectionError: on network failures
        requests.exceptions.Timeout: if the API takes too long
    """
    response = requests.post(
        GROQ_API_URL,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3,
            "max_tokens": 1500,
        },
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"]


def _parse_response(text: str) -> dict:
    """
    Parse the AI response into a dict.

    Handles common LLM bad habits:
      1. Markdown code fences:  ```json { ... } ```
      2. Preamble:              "Here is the analysis: { ... }"
      3. Trailing text:         { ... } Some explanation after.

    Falls back to regex extraction if standard parsing fails.
    Returns empty dict if all parsing attempts fail (finding stays unenriched).
    """
    text = text.strip()

    # Step 1: Strip markdown code fences if present
    # Matches ```json, ```JSON, ``` (with optional language tag)
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*```$", "", text)
    text = text.strip()

    # Step 2: Try direct JSON parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Step 3: Regex extraction — find the first {...} block in the text
    # re.DOTALL makes . match newlines, so this handles multi-line JSON
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    # Step 4: Give up — return empty dict, finding stays unenriched
    return {}


def _apply_enrichment(finding: Finding, data: dict) -> Finding:
    """
    Apply AI response data to a Finding, returning an enriched copy.

    Why use dataclasses.replace() instead of mutating in place?
      Immutability makes bugs easier to find. If a finding looks wrong,
      you can trace exactly where each field was set — either the parser
      (original) or this function (enrichment). Mutation makes that trail
      invisible.
    """
    if not data:
        return finding

    # Validate priority — only accept known values
    valid_priorities = {"critical", "high", "medium", "low"}
    priority = data.get("priority", "").lower()
    if priority not in valid_priorities:
        priority = finding.priority  # keep existing or None

    # Validate false_positive_likelihood
    valid_fp = {"low", "medium", "high"}
    fp_likelihood = data.get("false_positive_likelihood", "").lower()
    if fp_likelihood not in valid_fp:
        fp_likelihood = finding.false_positive_likelihood

    return replace(
        finding,
        ai_explanation=data.get("explanation") or finding.ai_explanation,
        priority=priority,
        priority_reason=data.get("priority_reason") or finding.priority_reason,
        suggested_commands=data.get("suggested_commands") or finding.suggested_commands,
        metasploit_modules=data.get("metasploit_modules") or finding.metasploit_modules,
        false_positive_likelihood=fp_likelihood,
        false_positive_reason=data.get("false_positive_reason") or finding.false_positive_reason,
        remediation=data.get("remediation") or finding.remediation,
    )
