import re
import json
import sys
import ollama

MODEL = "gemma2:2b"

SYSTEM_PROMPT = """You are a production log triage engine. You receive raw log lines from an \
unknown system (could be a web server, distributed filesystem, OS, or application).

Your job:
1. Ignore benign noise (routine INFO/notice/heartbeat/status lines).
2. Identify the SINGLE most severe anomaly, error, warning, or failure event.
3. Return ONE flat JSON object, no list, no nesting, with EXACTLY these keys:
{
  "service_name": "the component/daemon/module that emitted the event",
  "timestamp": "the date/time portion at the START of the line only",
  "error_severity": "one of: critical, error, warning, info",
  "suggested_remediation": "one concrete sentence on how to fix it"
}

For "timestamp", extract ONLY the date/time at the start of the line. Do NOT include
the hostname, process name, PID, or the message text.
Example: from "Jun 15 02:04:59 combo sshd[20882]: authentication failure" the timestamp
is "Jun 15 02:04:59".

Output ONLY the JSON. No prose, no markdown fences, no extra keys."""

ANOMALY_RE = re.compile(
    r"error|fail|fatal|denied|forbidden|exception|warn|timeout|refused|"
    r"unable|cannot|critical|panic|abort|corrupt|invalid|unauthorized",
    re.I,
)

TS_PATTERNS = [
    r"[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}",  # Apache
    r"\b\d{8}-\d{2}:\d{2}:\d{2}:\d{3}\b",                                    # HealthApp
    r"\b\d{6}\s+\d{6}\b",                                                    # HDFS
    r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b",                      # Linux
]


def clean_timestamp(ts):
    for pat in TS_PATTERNS:
        m = re.search(pat, ts)
        if m:
            return m.group(0)
    return ts


def prefilter(raw_text, max_lines=20):
    lines = [l.strip() for l in raw_text.splitlines() if l.strip()]
    suspects = [l for l in lines if ANOMALY_RE.search(l)]
    chosen = suspects or lines
    return "\n".join(chosen[:max_lines])


def triage(log_text):
    filtered = prefilter(log_text)
    resp = ollama.chat(
        model=MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": filtered},
        ],
        format="json",
        options={"temperature": 0},
    )
    return resp["message"]["content"]


def validate(raw, required=("service_name", "timestamp", "error_severity", "suggested_remediation")):
    cleaned = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    data = json.loads(cleaned)

    if isinstance(data, list):
        if not data:
            raise ValueError("Empty list returned")
        data = data[0]

    if isinstance(data, dict) and not any(k in data for k in required):
        for v in data.values():
            if isinstance(v, dict) and any(k in v for k in required):
                data = v
                break

    missing = [k for k in required if k not in data or data[k] in (None, "")]
    if missing:
        raise ValueError(f"Missing/empty keys: {missing}")

    result = {k: str(data[k]) for k in required}
    result["timestamp"] = clean_timestamp(result["timestamp"])
    return result


def run(log_text, retries=2):
    last_err = None
    for attempt in range(retries + 1):
        raw = triage(log_text)
        try:
            return validate(raw)
        except (json.JSONDecodeError, ValueError) as e:
            last_err = e
            print(f"  [retry {attempt + 1}] bad output: {e}", file=sys.stderr)
    raise RuntimeError(f"Failed after {retries + 1} attempts: {last_err}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r", errors="replace") as f:
            log_text = f.read()
    else:
        log_text = sys.stdin.read()

    if not log_text.strip():
        print("Error: no log data provided.", file=sys.stderr)
        sys.exit(1)

    result = run(log_text)
    print(json.dumps(result, indent=2))