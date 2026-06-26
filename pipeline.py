import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request

OLLAMA_URL = "http://localhost:11434/api/chat"
DEFAULT_MODEL = "gemma4:12b"
REQUEST_TIMEOUT = 600  # seconds per model call

# ---------------------------------------------------------------------------
# Output contract (fixed by us, never delegated to the model). Whatever prompt
# Stage 1 generates, this block is always appended so the JSON schema holds.
# ---------------------------------------------------------------------------
REQUIRED_KEYS = {
    "service_name",
    "timestamp",
    "error_severity",
    "suggested_remediation",
    "source_line",
}
VALID_SEVERITIES = {"warning", "error", "fatal"}

OUTPUT_CONTRACT = """TASK:
1. Ignore routine, healthy, successful, or purely informational lines.
2. Identify lines indicating failures, errors, invalid states, anomalies, or security events.
3. For each such line, return a JSON object with EXACTLY these keys:
   - service_name: the process/service/component that logged it; "unknown" if unclear.
   - timestamp: copied exactly from the line; empty string if absent.
   - error_severity: exactly one of "warning", "error", or "fatal".
   - suggested_remediation: one actionable sentence.
   - source_line: the exact original log line, copied verbatim.

Return ONLY a valid JSON array of these objects. No markdown fences, no explanation,
no preamble. If no errors are found, return an empty array: []"""

# Fallback prompt used when profiling is disabled or fails.
STATIC_SYSTEM_PROMPT = (
    "You are a log triage tool. You receive raw system/server log lines "
    "(syslog, kernel, application, or similar). The exact format may vary.\n\n"
    + OUTPUT_CONTRACT
)

# ---------------------------------------------------------------------------
# Stage 1: profiler
# ---------------------------------------------------------------------------
PROFILER_SYSTEM_PROMPT = (
    "You are a log-format analyst. You receive a sample of DISTINCT log line "
    "templates (repeated patterns already deduplicated) from ONE log file. "
    "Analyze them and describe how to triage THIS specific log.\n\n"
    "Return ONLY a JSON object (no prose, no markdown) with EXACTLY these keys:\n"
    '- "format_description": one sentence naming the log type/format.\n'
    '- "service_hint": one sentence on how to identify the service/component name.\n'
    '- "timestamp_hint": one sentence describing the timestamp format, or "none".\n'
    '- "benign_patterns": array of short lowercase substrings that mark ROUTINE, '
    'HEALTHY, successful, non-error lines (e.g. "startup succeeded", '
    '"session opened", "accepted password"). Be conservative: never include text '
    "that also appears in failures, errors, or anomalies.\n"
    '- "triage_guidance": 2-4 sentences of format-specific advice for spotting real '
    "failures/errors/anomalies in this log, including how to infer severity.\n\n"
    "Return ONLY the JSON object."
)

PROFILE_KEYS = {
    "format_description",
    "service_hint",
    "timestamp_hint",
    "benign_patterns",
    "triage_guidance",
}

DEFAULT_PROFILE = {
    "format_description": "raw system/server logs of an unknown format",
    "service_hint": "the token before the first colon, if present",
    "timestamp_hint": "leading timestamp if present",
    "benign_patterns": [],
    "triage_guidance": (
        "Flag lines containing failures, errors, invalid states, denials, timeouts, "
        "or crashes; ignore routine, successful, or informational lines."
    ),
}

# ---------------------------------------------------------------------------
# Template deduplication
# ---------------------------------------------------------------------------
# Lines worth keeping when --filter is enabled, and the guard that stops the
# benign filter from ever dropping a line that carries an explicit error signal.
KEYWORD_RE = re.compile(
    r"fail|error|invalid|denied|unable|cannot|can.t|refus|timeout|timed out|panic|oops|"
    r"segfault|fatal|warn|critical|alert|corrupt|reject|unauthor|abort|exception|"
    r"no such|out of memory|\boom\b|killed",
    re.IGNORECASE,
)

_PID_RE = re.compile(r"\[\d+\]")
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HEX_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")
_NUM_RE = re.compile(r"\d+")
_WS_RE = re.compile(r"\s+")
_SYSLOG_RE = re.compile(r"^[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+\S+\s+(?P<body>.*)$")


def template_key(line: str) -> str:
    """Normalize a log line so identical patterns collapse to one key."""
    text = line.strip()
    m = _SYSLOG_RE.match(text)
    if m:
        text = m.group("body")
    text = _PID_RE.sub("[]", text)
    text = _IP_RE.sub("#", text)
    text = _HEX_RE.sub("#", text)
    text = _NUM_RE.sub("#", text)
    return _WS_RE.sub(" ", text).strip()


def extract_timestamp(line: str) -> str:
    """Pull the leading syslog timestamp if present, else empty string."""
    m = re.match(r"^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)", line.strip())
    return m.group(1) if m else ""


def dedup_templates(lines: list, use_filter: bool) -> list:
    """Collapse raw lines into unique templates (first-seen order).

    Each item: {source_line, timestamp, occurrence_count}.
    """
    order = []
    by_key = {}
    for raw in lines:
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        if use_filter and not KEYWORD_RE.search(line):
            continue
        key = template_key(line)
        if not key:
            continue
        if key not in by_key:
            by_key[key] = {
                "source_line": line,
                "timestamp": extract_timestamp(line),
                "occurrence_count": 0,
            }
            order.append(key)
        by_key[key]["occurrence_count"] += 1
    return [by_key[k] for k in order]


# ---------------------------------------------------------------------------
# Model I/O
# ---------------------------------------------------------------------------
def call_gemma(content: str, system_prompt: str, model: str) -> str:
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": content},
        ],
        "stream": False,
        "think": False,
        "options": {"temperature": 0},
    }
    req = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    return body["message"]["content"]


def _strip_fences(raw: str) -> str:
    text = raw.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text[3:]
    if text.endswith("```"):
        text = text.rsplit("```", 1)[0]
    return text.strip()


def extract_json(raw: str) -> list:
    """Parse a JSON array out of model output, tolerating fences and preamble."""
    text = _strip_fences(raw)
    start, end = text.find("["), text.rfind("]")
    if start != -1 and end > start:
        text = text[start:end + 1]
    return json.loads(text)


def extract_profile_json(raw: str) -> dict:
    """Parse a JSON object out of model output, tolerating fences and preamble."""
    text = _strip_fences(raw)
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        text = text[start:end + 1]
    return json.loads(text)


# ---------------------------------------------------------------------------
# Stage 1: build the log profile
# ---------------------------------------------------------------------------
def build_profile(templates: list, model: str, sample_size: int):
    """Run one model call over a sample of templates to learn how to triage
    this log. Returns a normalized profile dict, or None on failure."""
    sample = sorted(templates, key=lambda t: t["occurrence_count"], reverse=True)
    sample_text = "\n".join(t["source_line"] for t in sample[:sample_size])
    try:
        raw = call_gemma(sample_text, PROFILER_SYSTEM_PROMPT, model)
        profile = extract_profile_json(raw)
    except (urllib.error.URLError, TimeoutError, OSError,
            json.JSONDecodeError, ValueError, KeyError) as e:
        print(f"Stage 1 profiling failed ({e}); falling back to default prompt.",
              file=sys.stderr)
        return None
    if not isinstance(profile, dict):
        return None

    clean = dict(DEFAULT_PROFILE)
    for k in ("format_description", "service_hint", "timestamp_hint", "triage_guidance"):
        v = profile.get(k)
        if isinstance(v, str) and v.strip():
            clean[k] = v.strip()
    bp = profile.get("benign_patterns")
    if isinstance(bp, list):
        clean["benign_patterns"] = [
            str(p).strip().lower() for p in bp if str(p).strip()
        ]
    return clean


def compose_extraction_prompt(profile: dict) -> str:
    """Assemble the Stage 2 system prompt: model-generated guidance + fixed contract."""
    return (
        f"You are a log triage tool analyzing {profile['format_description']}.\n\n"
        "LOG FORMAT NOTES:\n"
        f"- Service/component: {profile['service_hint']}\n"
        f"- Timestamp: {profile['timestamp_hint']}\n\n"
        "TRIAGE GUIDANCE FOR THIS LOG:\n"
        f"{profile['triage_guidance']}\n\n"
        + OUTPUT_CONTRACT
    )


def apply_benign_filter(templates: list, benign_patterns: list):
    """Drop templates matching a benign pattern, unless the line also carries an
    explicit error keyword (guard against the profiler over-filtering)."""
    if not benign_patterns:
        return templates, 0
    kept, dropped = [], 0
    for t in templates:
        line = t["source_line"].lower()
        if any(p in line for p in benign_patterns) and not KEYWORD_RE.search(line):
            dropped += 1
            continue
        kept.append(t)
    return kept, dropped


# ---------------------------------------------------------------------------
# Stage 2: triage
# ---------------------------------------------------------------------------
def validate_entries(entries: list) -> list:
    """Keep only objects with all required keys; coerce bad severities."""
    valid = []
    for e in entries:
        if not isinstance(e, dict) or not REQUIRED_KEYS.issubset(e.keys()):
            continue
        if e.get("error_severity") not in VALID_SEVERITIES:
            e["error_severity"] = "error"
        valid.append(e)
    return valid


def triage(templates: list, chunk_size: int, system_prompt: str, model: str):
    """Run the model over unique templates. Returns (errors, num_calls)."""
    rep_lines = [t["source_line"] for t in templates]
    count_by_line = {t["source_line"]: t["occurrence_count"] for t in templates}
    all_errors = []
    num_calls = 0

    for i in range(0, len(rep_lines), chunk_size):
        chunk = "\n".join(rep_lines[i:i + chunk_size])
        print(f"Triaging templates {i}-{i + len(rep_lines[i:i + chunk_size])} "
              f"of {len(rep_lines)}...", file=sys.stderr)
        try:
            num_calls += 1
            parsed = extract_json(call_gemma(chunk, system_prompt, model))
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            # Network/timeout: retrying the same chunk usually times out again.
            # Skip it so one slow chunk never loses the whole run's progress.
            print(f"Chunk starting at {i} failed ({e}); skipping.", file=sys.stderr)
            continue
        except (json.JSONDecodeError, ValueError, KeyError):
            print(f"Bad JSON on chunk starting at {i}, retrying...", file=sys.stderr)
            try:
                num_calls += 1
                parsed = extract_json(call_gemma(
                    "Your previous output was not valid JSON. "
                    "Return ONLY a valid JSON array.\n\n" + chunk,
                    system_prompt, model,
                ))
            except (urllib.error.URLError, TimeoutError, OSError,
                    json.JSONDecodeError, ValueError, KeyError):
                print(f"Chunk starting at {i} failed after retry, skipping.",
                      file=sys.stderr)
                continue
        all_errors.extend(validate_entries(parsed))

    # Re-attach occurrence counts and dedup model output.
    seen = set()
    deduped = []
    for e in all_errors:
        sig = (e.get("service_name"), e.get("timestamp"), e.get("source_line"))
        if sig in seen:
            continue
        seen.add(sig)
        e["occurrence_count"] = count_by_line.get(e.get("source_line"), 1)
        deduped.append(e)
    return deduped, num_calls


def print_summary(total_lines, unique_templates, triaged_templates,
                  num_calls, errors, elapsed, profiled):
    by_sev = {}
    for e in errors:
        by_sev[e["error_severity"]] = by_sev.get(e["error_severity"], 0) + 1
    print("\n--- Summary ---", file=sys.stderr)
    print(f"Raw lines processed  : {total_lines}", file=sys.stderr)
    print(f"Unique templates     : {unique_templates}", file=sys.stderr)
    if profiled:
        print(f"After benign filter  : {triaged_templates}", file=sys.stderr)
    print(f"Model calls (triage) : {num_calls}", file=sys.stderr)
    print(f"Errors found         : {len(errors)}", file=sys.stderr)
    for sev in ("fatal", "error", "warning"):
        if sev in by_sev:
            print(f"  {sev:<8}: {by_sev[sev]}", file=sys.stderr)
    print(f"Profiling            : {'on (Stage 1)' if profiled else 'off'}",
          file=sys.stderr)
    print(f"Elapsed              : {elapsed:.1f}s", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Two-stage log triage: profile the log, then extract errors as JSON.")
    parser.add_argument("logfile", help="Path to the raw log file")
    parser.add_argument("-o", "--output", default="output.json",
                        help="Output JSON file (default: output.json)")
    parser.add_argument("--chunk-size", type=int, default=50,
                        help="Unique lines per model call (default: 50)")
    parser.add_argument("--model", default=DEFAULT_MODEL,
                        help=f"Ollama model for both stages (default: {DEFAULT_MODEL})")
    parser.add_argument("--filter", action="store_true",
                        help="Keyword pre-filter before dedup (faster, lower recall)")
    parser.add_argument("--no-profile", action="store_true",
                        help="Disable Stage 1 profiling; use the static prompt")
    parser.add_argument("--profile-sample", type=int, default=120,
                        help="Templates sampled for Stage 1 profiling (default: 120)")
    args = parser.parse_args()

    start = time.perf_counter()

    with open(args.logfile, "r", errors="ignore") as f:
        lines = f.readlines()

    templates = dedup_templates(lines, use_filter=args.filter)
    print(f"Reduced {len(lines)} raw lines to {len(templates)} unique templates.",
          file=sys.stderr)

    unique_count = len(templates)
    profile = None
    if templates and not args.no_profile:
        print(f"Stage 1: profiling log format ({args.model})...", file=sys.stderr)
        profile = build_profile(templates, args.model, args.profile_sample)

    if profile:
        print("Stage 1 profile:", file=sys.stderr)
        print(f"  format   : {profile['format_description']}", file=sys.stderr)
        print(f"  guidance : {profile['triage_guidance']}", file=sys.stderr)
        print(f"  benign   : {profile['benign_patterns']}", file=sys.stderr)
        templates, dropped = apply_benign_filter(templates, profile["benign_patterns"])
        print(f"Benign filter dropped {dropped} templates; {len(templates)} to triage.",
              file=sys.stderr)
        system_prompt = compose_extraction_prompt(profile)
    else:
        system_prompt = STATIC_SYSTEM_PROMPT

    if not templates:
        errors, num_calls = [], 0
    else:
        print("Stage 2: triaging...", file=sys.stderr)
        errors, num_calls = triage(templates, args.chunk_size, system_prompt, args.model)

    with open(args.output, "w") as f:
        json.dump(errors, f, indent=2)

    print(json.dumps(errors, indent=2))
    elapsed = time.perf_counter() - start
    print_summary(len(lines), unique_count, len(templates),
                  num_calls, errors, elapsed, profiled=bool(profile))
    print(f"\nWrote {len(errors)} errors to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
