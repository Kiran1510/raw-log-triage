import re
import json
import sys
import ollama

MODEL = "gemma2:2b"

# Severity ranking so we can compare events found in different chunks.
SEVERITY_RANK = {"critical": 4, "error": 3, "warning": 2, "info": 1, "none": 0}

SYSTEM_PROMPT = """You are a production log triage engine. You receive a CHUNK of raw log lines
from an unknown system (web server, distributed filesystem, OS, or application).

Find the SINGLE most severe anomaly, error, warning, or failure in THIS chunk.
Ignore benign/routine lines (INFO, notice, heartbeat, status).

If the chunk contains NO anomaly at all, return exactly: {"error_severity": "none"}

Otherwise return ONE flat JSON object with EXACTLY these keys:
{
  "service_name": "the component/daemon/module that emitted the event (name only, no hostname)",
  "timestamp": "ONLY the date/time at the start of that line, not the message or host",
  "error_severity": "one of: critical, error, warning, info",
  "suggested_remediation": "one concrete sentence on how to fix it"
}

Example: from "Jun 15 02:04:59 combo sshd[20882]: authentication failure" the
timestamp is "Jun 15 02:04:59" and the service_name is "sshd".

Output ONLY the JSON. No prose, no markdown, no extra keys."""

# Cheap pre-pass: skip chunks with no hint of trouble, to save model calls.
# This is a SPEED optimization only, not the triage decision itself.
HINT_RE = re.compile(
    r"error|fail|fatal|denied|forbidden|exception|warn|timeout|refused|"
    r"unable|cannot|critical|panic|abort|corrupt|invalid|unauthorized|reject|crash",
    re.I,
)


def chunks(lines, size):
    for i in range(0, len(lines), size):
        yield lines[i:i + size]


def parse_json(raw):
    cleaned = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    data = json.loads(cleaned)
    if isinstance(data, list):
        data = data[0] if data else {}
    return data if isinstance(data, dict) else {}


def ask_chunk(text):
    """Ask Gemma for the worst event in one chunk. Returns dict or None."""
    resp = ollama.chat(
        model=MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": text},
        ],
        format="json",
        options={"temperature": 0},
    )
    try:
        data = parse_json(resp["message"]["content"])
    except (json.JSONDecodeError, IndexError):
        return None
    if data.get("error_severity", "none").lower() == "none":
        return None
    if not all(k in data for k in ("service_name", "timestamp", "error_severity", "suggested_remediation")):
        return None
    return data


def rank(event):
    return SEVERITY_RANK.get(str(event.get("error_severity", "none")).lower(), 0)


def triage(raw_text, chunk_size=150):
    lines = [l.strip() for l in raw_text.splitlines() if l.strip()]
    if not lines:
        raise ValueError("No log data found")

    best = None
    scanned = 0
    for batch in chunks(lines, chunk_size):
        # speed pre-pass: only spend a model call on chunks that look suspicious
        if not any(HINT_RE.search(l) for l in batch):
            continue
        scanned += 1
        event = ask_chunk("\n".join(batch))
        if event and (best is None or rank(event) > rank(best)):
            best = event

    # Fallback: if the hint pre-pass skipped everything, scan the whole log in windows.
    if best is None:
        for batch in chunks(lines, chunk_size):
            event = ask_chunk("\n".join(batch))
            if event and (best is None or rank(event) > rank(best)):
                best = event

    if best is None:
        raise ValueError("No anomaly found in log")

    print(f"  [scanned {scanned} suspicious chunk(s)]", file=sys.stderr)
    # keep only required keys, canonical order, as strings
    required = ("service_name", "timestamp", "error_severity", "suggested_remediation")
    return {k: str(best[k]) for k in required}


if __name__ == "__main__":
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r", errors="replace") as f:
            log_text = f.read()
    else:
        log_text = sys.stdin.read()

    if not log_text.strip():
        print("Error: no log data provided.", file=sys.stderr)
        sys.exit(1)

    result = triage(log_text)
    print(json.dumps(result, indent=2))