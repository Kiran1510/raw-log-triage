# HACKATHON HANDOFF — Log Triage Pipeline

## Context

5-hour hackathon. Theme: "AI-First Developer Efficiencies." Pure code, no frontend UIs allowed. We chose Track 2: The Raw Log Triage Pipeline (Log-to-JSON).

## What This Project Does

A Python CLI tool that reads raw production system/server logs, routes them through a local Google Gemma model via Ollama, and outputs a validated JSON array of detected errors. Each error object contains: `service_name`, `timestamp`, `error_severity`, `suggested_remediation`, and `source_line`.

## Hardware & Model

- Machine: M1 Max MacBook Pro, 64GB unified RAM
- Model: `gemma4:12b` running locally via Ollama
- API: Ollama REST API at `http://localhost:11434/api/chat`
- Thinking mode MUST be disabled (`"think": False`) or the model hangs on large inputs
- The model uses native system prompt support via the `"system"` role in messages

## Data

- Source: Loghub repository (https://github.com/logpai/loghub), Linux dataset
- Full file: `~/hackathon/Linux.log` (~25,567 lines, 2.25MB, some non-UTF-8 bytes)
- Test file: `~/hackathon/test_small.txt` (50 lines)
- Sample file: `~/hackathon/sample_logs.txt` (500 lines)
- Log format: `Mon DD HH:MM:SS combo <service>: <message>` (standard syslog, no year, hostname always "combo")
- There are NO explicit severity labels in the logs. The model must infer severity from message content (e.g., "failed", "invalid", "error" in the message text).

## Current Working Script

File: `~/hackathon/pipeline.py`

```python
import json
import sys
import requests

SYSTEM_PROMPT = """You are a log triage tool. You receive raw Linux syslog output.

TASK:
1. Ignore routine boot messages, hardware initialization, driver loading, and successful startup lines.
2. Identify lines indicating failures, errors, invalid states, or anomalies.
3. For each error, return a JSON object with:
   - service_name: the process/service that logged it (e.g. "kernel", "smartd")
   - timestamp: preserved exactly from the log (e.g. "Jun  9 06:06:20")
   - error_severity: "warning", "error", or "fatal"
   - suggested_remediation: one actionable sentence
   - source_line: the exact original log line that triggered this detection

Return ONLY a valid JSON array. No markdown fences, no explanation, no preamble.
If no errors are found, return an empty array: []"""


def call_gemma(log_chunk: str) -> str:
    resp = requests.post(
        "http://localhost:11434/api/chat",
        json={
            "model": "gemma4:12b",
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": log_chunk},
            ],
            "stream": False,
            "think": False,
        },
    )
    resp.raise_for_status()
    return resp.json()["message"]["content"]


def extract_json(raw: str) -> list:
    text = raw.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1]
    if text.endswith("```"):
        text = text.rsplit("```", 1)[0]
    return json.loads(text.strip())


def main():
    if len(sys.argv) < 2:
        print("Usage: python pipeline.py <logfile>", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1], "r", errors="ignore") as f:
        lines = f.readlines()

    chunk_size = 100
    all_errors = []

    for i in range(0, len(lines), chunk_size):
        chunk = "".join(lines[i:i + chunk_size])
        print(f"Processing lines {i}-{i + len(lines[i:i + chunk_size])}...", file=sys.stderr)
        raw = call_gemma(chunk)
        try:
            parsed = extract_json(raw)
            all_errors.extend(parsed)
        except (json.JSONDecodeError, ValueError):
            print(f"Bad JSON on chunk {i}, retrying...", file=sys.stderr)
            raw = call_gemma(
                "Your previous output was not valid JSON. "
                "Return ONLY a valid JSON array.\n\n" + chunk
            )
            try:
                parsed = extract_json(raw)
                all_errors.extend(parsed)
            except (json.JSONDecodeError, ValueError):
                print(f"Chunk {i} failed after retry, skipping.", file=sys.stderr)

    with open("output.json", "w") as f:
        json.dump(all_errors, f, indent=2)

    print(json.dumps(all_errors, indent=2))
    print(f"\nWrote {len(all_errors)} errors to output.json", file=sys.stderr)


if __name__ == "__main__":
    main()
```

## What Works

- 50-line test: returns clean valid JSON in seconds, correctly identifies real errors
- 500-line sample: returns 8 errors with correct service names, timestamps, severity, and remediation — all valid JSON, no retries needed
- Full 25,567-line file: chunked processing at 100 lines per chunk, currently running/untested for completion
- Markdown fence stripping in extract_json works
- Retry logic works on bad JSON responses
- UTF-8 encoding errors handled via errors="ignore"

## What Still Needs To Be Done

### HIGH PRIORITY (required for judging)

1. **Add `source_line` field**: The hackathon brief says "locate the precise line causing an anomaly." The SYSTEM_PROMPT in the script above already includes source_line. Verify the model actually returns it. If not, the prompt may need reinforcement.

2. **Schema validation**: Add validation that every returned object has all 5 required keys. Drop entries missing keys instead of crashing:
   ```python
   REQUIRED_KEYS = {"service_name", "timestamp", "error_severity", "suggested_remediation", "source_line"}
   
   def validate_entries(entries: list) -> list:
       return [e for e in entries if REQUIRED_KEYS.issubset(e.keys())]
   ```

3. **Verify full-file run completes**: `python pipeline.py Linux.log` must run to completion and produce output.json. If any chunks fail after retry, they get skipped (already handled). Confirm the final output.json is valid.

4. **Edge case: empty input**: Handle the case where the log file is empty or contains no errors. Should output `[]`.

5. **Edge case: unseen log formats**: The organizers will provide alternative unseen log samples. The HDFS logs from loghub have a completely different format. The prompt should be generic enough to handle different syslog-style formats, not just the Linux one.

### MEDIUM PRIORITY (differentiation for judging)

6. **Deduplication**: Chunked processing may produce duplicate errors if the same event spans a chunk boundary or appears in retry output. Add dedup by comparing (service_name, timestamp, source_line) tuples.

7. **Summary stats**: After the JSON output, print a brief summary: total lines processed, total errors found, breakdown by severity. Judges like visible metrics.

8. **Output to file flag**: Add `--output` or `-o` CLI flag to specify output filename instead of hardcoded "output.json". Argparse is fine.

9. **Timing**: Add wall-clock timing to show how fast the pipeline runs. Demonstrates the tool is practical.

### LOW PRIORITY (polish, do last)

10. **README.md**: Required for repo review. Include:
    - What the tool does (one paragraph)
    - Prerequisites (Python 3, requests, Ollama with gemma4:12b)
    - How to run: `python pipeline.py <logfile>`
    - Example output
    - Architecture: reads file → chunks → Gemma API → JSON validation → merged output

11. **Git repo**: `git init && git add -A && git commit -m "initial submission"`

12. **requirements.txt**: Just `requests` — that's the only external dependency.

## Technical Decisions & Gotchas

- `"think": False` is MANDATORY in every API call or the model does silent chain-of-thought and hangs on large inputs
- `"stream": False` is required to get complete responses (otherwise you get token-by-token streaming)
- Chunk size of 100 lines is the tested sweet spot. 500 lines in a single prompt worked once but is risky for the full file. Do not go above 200.
- The model sometimes wraps JSON in markdown fences despite being told not to. extract_json handles this.
- The model sometimes returns conversational preamble before the JSON. If this happens, you may need regex to find the first `[` and last `]` in the output.
- Linux.log has non-UTF-8 bytes. Always open with `errors="ignore"`.
- Ollama API endpoint: `http://localhost:11434/api/chat` — use /api/chat not /api/generate, because Gemma 4 supports native system role via chat.

## Hackathon Judging Criteria (inferred from brief)

- Does the script run end-to-end on a provided log file?
- Is the JSON output syntactically valid and parseable?
- Does each object contain the 4 required fields (service_name, timestamp, error_severity, suggested_remediation)?
- Does the tool handle edge cases (bad model output, encoding errors, empty files)?
- Does it work on unseen log samples from the organizers?
- Is the code clean and the repo reviewable?

## File Structure

```
~/hackathon/
├── pipeline.py          # Main script
├── Linux.log            # Full dataset (25,567 lines)
├── sample_logs.txt      # 500-line test sample
├── test_small.txt       # 50-line test sample
├── output.json          # Generated output (after running on full file)
├── linux_logs.tar.gz    # Original download
├── README.md            # TODO: create for submission
└── requirements.txt     # TODO: create (just "requests")
```
