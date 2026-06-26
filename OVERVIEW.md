# Project Overview

A single map of the whole repo and how its parts fit together. For quickstart usage see
[README.md](README.md); for the evaluation rubric see [evaluation/EVALUATION.md](evaluation/EVALUATION.md).

## Purpose

GDG × Northeastern Hackathon, **Track 2 — Raw Log Triage (Log-to-JSON)**. A local Python
utility that consumes a raw, unstructured log dump, uses a **Gemma** model to strip benign
noise and isolate the real failures, and emits **strictly-validated JSON** ready for a
webhook/DB. No frontend — pure code plumbing.

## Directory map

```
pipeline.py            Reference approach: two-stage, format-adaptive, emits a JSON ARRAY of errors
requirements.txt       (none — Python 3 stdlib only; needs a Gemma backend)
README.md              Quickstart + how it works
HANDOFF.md             Historical handoff (superseded — see note at its top)
data/
  loghub/              All 16 loghub 2k datasets (Android … Zookeeper)
  samples/             16 reproducible 300-line eval samples (from make_samples.py)
  Linux.log            Full Linux dataset (25,567 lines); HDFS_2k.log + small samples too
evaluation/            Approach-agnostic scoring harness
  eval.py                Scores one output JSON (hard checks A–G + soft recall/leakage)
  run_all.py             Runs an approach over all datasets → aggregate scorecard
  signatures.py          Per-dataset ground truth (level-based + keyword)
  make_samples.py        Seeded sampler
  EVALUATION.md          Rubric + expectations + results
results/               Frozen pre-tuning baseline (gemma2:9b): outputs + scorecard
log-org-with-dataset/  Collaborator's alternate approach (single most-severe anomaly, gemma2:2b)
outputs/               Generated run outputs (gitignored)
```

## Reference pipeline — `pipeline.py`

Format-adaptive, two-stage. Pipeline: **read → dedup → profile → triage → validate → JSON**.

- **Stage 0 — Deduplicate** ([`dedup_templates`](pipeline.py) / [`template_key`](pipeline.py)).
  Collapses repeated log lines into unique templates by masking the variable parts
  (timestamp/host prefix, `[pid]`, IPs, hex, digit runs, and `key=value` values). Turns
  25,567 Linux lines into ~700 templates → far fewer model calls, and a per-finding
  `occurrence_count`.
- **Stage 1 — Profile** ([`build_profile`](pipeline.py) / `PROFILER_SYSTEM_PROMPT`). One model
  call over the most-frequent templates returns a JSON **log profile**: `format_description`,
  `service_hint`, `timestamp_hint`, `severity_scheme`, `benign_patterns`, `triage_guidance`.
  This is what makes it adapt to unseen formats. Falls back to a default profile on failure.
- **Stage 2 — Triage** ([`apply_benign_filter`](pipeline.py) → [`compose_extraction_prompt`](pipeline.py)
  → [`triage`](pipeline.py)). Drops the profiled benign templates (with an error-keyword guard),
  builds a **log-tailored** prompt, and extracts JSON in chunks. The model writes the
  *guidance*, but a fixed `OUTPUT_CONTRACT` (required keys + "JSON only") is always appended,
  so a bad generated prompt can't break the schema.

**Output contract** — a JSON array of objects with `service_name`, `timestamp`,
`error_severity` (∈ {warning, error, fatal}), `suggested_remediation`, `source_line`
(verbatim), `occurrence_count`. Clean JSON to **stdout** + the output file; the human-readable
run report (profile, counts, timing) goes to **stderr**.

**Robustness** — `_strip_fences` removes markdown fences and `<thought>`/`<think>` reasoning
traces; bad JSON triggers one retry; network/timeout errors **skip** the chunk (never crash
the run); `validate_entries` drops incomplete objects and coerces bad severities; output is
re-deduped on `(service_name, timestamp, source_line)`.

**Backends** (`--provider`, both use a Gemma model):
- `ollama` (default) — local Ollama at `/api/chat`, `gemma4:12b`, `think:false`.
- `google` — free Gemma via Google AI Studio's OpenAI-compatible API (`gemma-4-31b-it`,
  `GEMINI_API_KEY`). System prompt is folded into the user turn (Gemma has no system role
  there); a CA-bundle SSL context fixes cert verification on python.org Python.

CLI: `logfile`, `-o/--output`, `--provider`, `--model`, `--chunk-size`, `--filter`,
`--no-profile`, `--profile-sample`.

## Evaluation harness — `evaluation/`

**Approach-agnostic**: `eval.py` only reads an output JSON, never imports the pipeline — so
any approach is judged identically.

- [`signatures.py`](evaluation/signatures.py) — ground truth per dataset. **Level-based**
  (error = WARN/ERROR/FATAL, benign = INFO/DEBUG) for the leveled logs (HDFS, BGL, Hadoop,
  OpenStack, Spark, Zookeeper, Android, Windows); **keyword-based** for the rest (Apache, HPC,
  HealthApp, Linux, Mac, OpenSSH, Proxifier, Thunderbird); generic `DEFAULT` otherwise.
- [`eval.py`](evaluation/eval.py) — hard checks **A** JSON validity, **B** schema, **C**
  severity, **D** no hallucinated `source_line` (whitespace-insensitive), **E** timestamp ⊆
  source_line, **F** dedup, **G** occurrence_count sane; soft metrics **H** recall, **I**
  benign leakage, plus an independent occurrence-count cross-check and remediation check.
- [`run_all.py`](evaluation/run_all.py) — runs the pipeline over every `data/samples/*.log`
  and prints an aggregate scorecard. [`make_samples.py`](evaluation/make_samples.py) — seeded
  300-line samples.

## Results / baseline (`results/`)

Frozen **pre-tuning** baseline (`gemma2:9b`, 300-line samples): **9/16 hard-pass · 88% mean
recall (curated) · 10 benign leakage**. Most failures are weak-model artifacts (`D`/`E`) that
clear on the judging-grade `gemma-4-31b-it`. Spark (all-INFO) correctly returns `[]`. See
[evaluation/EVALUATION.md](evaluation/EVALUATION.md) for the full reading.

## Secondary approach (`log-org-with-dataset/`)

A collaborator's alternate design: heuristic **prefilter → `gemma2:2b` (`format="json"`) →
validate → retry**, emitting the **single most-severe anomaly** as one JSON object with 4
fields (no `source_line`/`occurrence_count`). Same generalize-across-formats goal, different
shape from the array-producing reference pipeline. See its own
[README](log-org-with-dataset/README.md).

## How to run

```bash
# triage a log → JSON (local Ollama, default gemma4:12b)
python pipeline.py data/HDFS_2k.log -o out.json

# free cloud Gemma instead (no local model)
export GEMINI_API_KEY=...        # https://aistudio.google.com/apikey
python pipeline.py data/HDFS_2k.log -o out.json --provider google

# score it, or benchmark across all 16 datasets
python evaluation/eval.py data/HDFS_2k.log out.json hdfs
python evaluation/run_all.py --model gemma2:9b
```

## Suggested cleanups (not yet applied — proposals only)

- **`HANDOFF.md` is historical** — it describes the original `requests`-based, 100-line-chunk
  script that the current `pipeline.py` (stdlib `urllib`, dedup, two-stage, argparse) has
  superseded. A "superseded" note is now at its top; could also move under `docs/history/`.
- **Root scratch artifacts** (`*.stderr`, `run_all_*.log`, `*_out.json`, etc.) clutter the
  local working tree but are **gitignored** (not in the cloned repo). Optional: a `scratch/` dir.
- **`log-org-with-dataset/`** has `triage.py`, `triage-cr.py`, and `test.py` (which *differ*) —
  worth a one-line note in its README on which is canonical.
- Merged remote branches (`additional-data`, `alaska-log-org`) could be pruned.
