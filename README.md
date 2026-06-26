# Raw Log Triage Pipeline (Log-to-JSON)

An AI-first developer utility: it consumes a raw system/server log, strips benign noise,
and emits a validated JSON array of the real failures — ready for a webhook or DB. Built
for the "AI-First Developer Efficiencies" hackathon, Track 2.

The tool is **format-adaptive**: a two-stage pipeline first *profiles* an unknown log
(detecting its format, severity scheme, and routine noise), then triages it with a
tailored prompt — so it works on Linux syslog, Hadoop HDFS, and (with no code changes)
formats it hasn't seen. It runs against a local **Gemma** model via Ollama and depends on
**nothing outside the Python standard library**.

## Layout

```
pipeline.py        Reference two-stage triage tool (profile -> triage)
data/              Log datasets to triage (Linux, HDFS, samples; add more from loghub)
evaluation/        Approach-agnostic scoring harness for any triage approach
  ├─ eval.py         Scores an output JSON against the rubric
  ├─ signatures.py   Per-dataset ground-truth (extensible)
  ├─ EVALUATION.md   The rubric + expectations + results
  └─ README.md       How collaborators score their own approach
HANDOFF.md         Original project handoff notes
```

## Prerequisites

- Python 3 (standard library only — no `pip install` needed)
- [Ollama](https://ollama.com) running locally with a Gemma model, e.g. `ollama pull gemma4:12b`

## Quickstart

```bash
# Triage a log into JSON
python pipeline.py data/HDFS_2k.log -o out.json

# Score the output against the rubric
python evaluation/eval.py data/HDFS_2k.log out.json hdfs
```

Useful flags: `--model <name>` (e.g. `gemma2:9b` for speed), `--no-profile` (skip Stage 1),
`--filter` (keyword pre-filter), `--chunk-size N`.

## How it works

1. **Deduplicate** — collapse repeated log templates (e.g. 25,567 lines → ~700 unique),
   masking variable parts (timestamps, PIDs, IPs, `key=value`). Massive speedup + an
   `occurrence_count` per finding.
2. **Stage 1 — Profile** — one model call over the most-frequent templates returns a JSON
   profile: format, service/timestamp hints, severity scheme, and benign noise patterns.
3. **Stage 2 — Triage** — drop the profiled benign patterns, then extract validated JSON
   with a log-tailored prompt. A fixed output contract guarantees the schema regardless of
   what Stage 1 produces; bad model output is retried, and timeouts are skipped (never
   crashing the run).

See [evaluation/EVALUATION.md](evaluation/EVALUATION.md) for measured results (e.g. the
HDFS precision fix: benign false positives 2 → 0 with no recall loss).
