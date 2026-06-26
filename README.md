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
pipeline.py          Reference two-stage triage tool (profile -> triage)
data/
  ├─ loghub/         All 16 loghub 2k datasets (Android … Zookeeper)
  ├─ samples/        300-line eval samples (one per dataset; reproducible)
  └─ Linux.log …     Full Linux dataset + extras
evaluation/          Approach-agnostic scoring harness + benchmark driver
  ├─ eval.py           Scores one output JSON against the rubric
  ├─ run_all.py        Runs an approach over all datasets -> aggregate scorecard
  ├─ make_samples.py   Regenerates data/samples/ from data/loghub/
  ├─ signatures.py     Per-dataset ground truth (level-based + keyword)
  ├─ EVALUATION.md     Rubric + expectations + results
  └─ README.md         Contract, scoring, and benchmark instructions
HANDOFF.md           Original project handoff notes
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

## Benchmark across all 16 loghub datasets

One command runs the pipeline over every dataset in `data/samples/` and prints an
aggregate scorecard (hard checks, recall, benign leakage per dataset):

```bash
python evaluation/run_all.py --model gemma4:12b        # full-quality pass
python evaluation/run_all.py --model gemma2:9b         # faster pass
python evaluation/run_all.py --only hdfs,linux         # a subset
```

Outputs go to `outputs/` (gitignored). To run two models **in parallel** and compare,
each teammate runs `run_all.py` with a different `--model` and diffs the scorecards.
Full instructions, the output contract, and how to add datasets:
[evaluation/README.md](evaluation/README.md).

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
