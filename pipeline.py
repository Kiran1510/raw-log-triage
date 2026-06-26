import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "gemma4:12b"
REQUEST_TIMEOUT = 600  # seconds per model call

SYSTEM_PROMPT = """You are a log triage tool. You receive raw system/server log lines \
(syslog, kernel, application, or similar formats). The exact format may vary between inputs.

TASK:
1. Ignore routine boot messages, hardware initialization, driver loading, and successful
   startup/shutdown lines.
2. Identify lines indicating failures, errors, invalid states, anomalies, or security events.
3. For each such line, return a JSON object with EXACTLY these keys:
   - service_name: the process/service that logged it (e.g. "kernel", "sshd", "smartd").
     Infer it from the line; use "unknown" if it cannot be determined.
   - timestamp: copied exactly from the log line (e.g. "Jun  9 06:06:20"). Empty string if absent.
   - error_severity: exactly one of "warning", "error", or "fatal", inferred from the message.
   - suggested_remediation: one actionable sentence.
   - source_line: the exact original log line that triggered this detection, copied verbatim.

Return ONLY a valid JSON array of these objects. No markdown fences, no explanation, no preamble.
If no errors are found, return an empty array: []"""

REQUIRED_KEYS = {
    "service_name",
    "timestamp",
    "error_severity",
    "suggested_remediation",
    "source_line",
}
VALID_SEVERITIES = {"warning", "error", "fatal"}

# Lines worth keeping when --filter is enabled (obvious error/anomaly signals).
KEYWORD_RE = re.compile(
    r"fail|error|invalid|denied|unable|cannot|can.t|refus|timeout|timed out|panic|oops|"
    r"segfault|fatal|warn|critical|alert|corrupt|reject|unauthor|abort|exception|"
    r"no such|out of memory|\boom\b|killed",
    re.IGNORECASE,
)

# Patterns whose values vary per occurrence but don't change the template identity.
_PID_RE = re.compile(r"\[\d+\]")
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HEX_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")
_NUM_RE = re.compile(r"\d+")
_WS_RE = re.compile(r"\s+")
# Syslog prefix: "Mon DD HH:MM:SS host service: message" -> capture the message body.
_SYSLOG_RE = re.compile(
    r"^[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+\S+\s+(?P<body>.*)$"
)


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
    """Collapse raw lines into unique templates.

    Returns a list of dicts (first-seen order) with keys:
    source_line, timestamp, occurrence_count.
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


def call_gemma(log_chunk: str) -> str:
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": log_chunk},
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


def extract_json(raw: str) -> list:
    """Parse a JSON array out of model output, tolerating fences and preamble."""
    text = raw.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text[3:]
    if text.endswith("```"):
        text = text.rsplit("```", 1)[0]
    text = text.strip()
    # Slice to the outermost JSON array if the model added conversational text.
    start = text.find("[")
    end = text.rfind("]")
    if start != -1 and end != -1 and end > start:
        text = text[start:end + 1]
    return json.loads(text)


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


def triage(templates: list, chunk_size: int) -> tuple:
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
            parsed = extract_json(call_gemma(chunk))
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
                    "Return ONLY a valid JSON array.\n\n" + chunk
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


def print_summary(total_lines, num_templates, num_calls, errors, elapsed):
    by_sev = {}
    for e in errors:
        by_sev[e["error_severity"]] = by_sev.get(e["error_severity"], 0) + 1
    print("\n--- Summary ---", file=sys.stderr)
    print(f"Raw lines processed : {total_lines}", file=sys.stderr)
    print(f"Unique templates    : {num_templates}", file=sys.stderr)
    print(f"Model calls          : {num_calls}", file=sys.stderr)
    print(f"Errors found         : {len(errors)}", file=sys.stderr)
    for sev in ("fatal", "error", "warning"):
        if sev in by_sev:
            print(f"  {sev:<8}: {by_sev[sev]}", file=sys.stderr)
    print(f"Elapsed              : {elapsed:.1f}s", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Triage raw logs into a validated JSON array of errors.")
    parser.add_argument("logfile", help="Path to the raw log file")
    parser.add_argument("-o", "--output", default="output.json",
                        help="Output JSON file (default: output.json)")
    parser.add_argument("--chunk-size", type=int, default=50,
                        help="Unique lines per model call (default: 50)")
    parser.add_argument("--filter", action="store_true",
                        help="Keyword pre-filter before dedup (faster, lower recall)")
    args = parser.parse_args()

    start = time.perf_counter()

    with open(args.logfile, "r", errors="ignore") as f:
        lines = f.readlines()

    templates = dedup_templates(lines, use_filter=args.filter)
    print(f"Reduced {len(lines)} raw lines to {len(templates)} unique templates.",
          file=sys.stderr)

    if not templates:
        errors, num_calls = [], 0
    else:
        errors, num_calls = triage(templates, args.chunk_size)

    with open(args.output, "w") as f:
        json.dump(errors, f, indent=2)

    print(json.dumps(errors, indent=2))
    elapsed = time.perf_counter() - start
    print_summary(len(lines), len(templates), num_calls, errors, elapsed)
    print(f"\nWrote {len(errors)} errors to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
