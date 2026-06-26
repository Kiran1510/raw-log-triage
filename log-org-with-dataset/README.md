# Log Triage Pipeline (Log-to-JSON)

**GDG x Northeastern Hackathon — Track 2**
A local Python micro-utility that consumes a raw, unstructured log dump, uses a
local **Gemma** model to strip benign noise and isolate the single most severe
anomaly, and emits a strictly-validated JSON object ready for webhook/database
injection.

## What it does

```
raw logs  ->  heuristic prefilter  ->  Gemma triage  ->  schema validation  ->  clean JSON
```

Given gigabytes of asynchronous logs, finding what actually failed normally means
manual regex spelunking. This tool collapses that into one command and returns a
machine-consumable event:

```json
{
  "service_name": "mod_jk",
  "timestamp": "Sun Dec 04 04:47:44 2005",
  "error_severity": "error",
  "suggested_remediation": "Check the mod_jk worker configuration and confirm the backend Tomcat connector is reachable."
}
```

## Why it generalizes

The same script handles four very different log formats with no per-format code:

| Format    | Example anomaly                              |
|-----------|----------------------------------------------|
| Apache    | `[error] mod_jk child workerEnv in error state 6` |
| HDFS      | `WARN ...DataXceiver: Got exception while serving` |
| Linux     | `sshd(pam_unix): authentication failure`     |
| HealthApp | `saveHealthDetailData() ...`                 |

## Reliability design (four layers)

1. **Prefilter** — a broad anomaly regex strips routine INFO/notice/heartbeat
   lines so a small model only sees candidate events. Falls back to a head sample
   if nothing matches, so the model is never starved of input.
2. **Constrained decoding** — Ollama's `format="json"` + `temperature=0` makes
   output deterministic and structurally valid JSON.
3. **Validation** — parses, unwraps stray lists/nesting, drops extra keys, checks
   all four required keys are present and non-empty, and re-serializes.
4. **Retry loop** — on malformed/incomplete output the model is re-queried before
   the pipeline gives up.

## Setup

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# install + start the model
ollama pull gemma2:2b
```

## Usage

```bash
# from a file
python triage.py sample_production_logs.txt

# or from a stream (webhook-style)
cat Linux_2k.log | python triage.py
```

## Files

- `triage.py` — the pipeline
- `requirements.txt` — Python deps
- `Apache_2k.txt`, `HDFS_2k.log`, `Linux_2k.log`, `HealthApp_2k.log` — test inputs
