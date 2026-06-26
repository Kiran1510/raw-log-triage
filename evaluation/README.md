# Evaluation Pipeline

A shared, **approach-agnostic** harness for scoring log-triage tools. Bring your own
approach — `eval.py` only looks at your output JSON, never your code — so collaborators
can compare different triage strategies on the same datasets and rubric.

## The contract

Your approach reads a log file from [`../data/`](../data/) and writes a **JSON array** of
objects, each with:

| field | meaning |
|---|---|
| `service_name` | process/service/component that logged it |
| `timestamp` | copied verbatim from the line (or "") |
| `error_severity` | one of `warning`, `error`, `fatal` |
| `suggested_remediation` | one actionable sentence |
| `source_line` | the exact original line, verbatim |
| `occurrence_count` | how many input lines this represents (int ≥ 1) |

## Scoring your approach

```bash
# 1. run YOUR tool to produce an output JSON
your_tool data/HDFS_2k.log > my_output.json

# 2. score it
python evaluation/eval.py data/HDFS_2k.log my_output.json hdfs
```

Hard checks (A–G) must pass: JSON validity, schema, severity, **no hallucinated
source_line**, timestamp fidelity, dedup, and an `occurrence_count` fabrication guard.
Soft metrics: **recall** (known errors surfaced) and **benign leakage** (false positives).
Full rubric: [EVALUATION.md](EVALUATION.md).

## Adding a dataset (e.g. the rest of loghub)

Each dataset needs ground-truth signatures. Add an entry to
[`signatures.py`](signatures.py):

```python
"apache": {
    "error":  [r"\[error\]", "File does not exist", "client denied"],
    "benign": [r"\[notice\]", "resuming normal operations"],
},
```

then run `python evaluation/eval.py data/Apache_2k.log out.json apache`. Datasets with no
entry use a generic default (approximate recall/precision).

## Reference approach

The repo's [`../pipeline.py`](../pipeline.py) is the reference two-stage triage tool
(profile → triage). Example end-to-end:

```bash
python pipeline.py data/HDFS_2k.log -o out.json     # produce output
python evaluation/eval.py data/HDFS_2k.log out.json hdfs   # score it
```

## Running the full benchmark (all 16 loghub datasets)

The benchmark inputs are `data/samples/*.log` — a 300-line random sample per dataset
(committed, so everyone runs the **same** inputs). `run_all.py` runs the pipeline on each,
scores it, and prints an aggregate scorecard.

### Prerequisites

```bash
# Ollama running, plus whichever model(s) you'll benchmark:
ollama pull gemma4:12b      # full-quality
ollama pull gemma2:9b       # faster
```

### Run

```bash
# from the repo root (local Ollama, default):
python evaluation/run_all.py --model gemma4:12b      # one full pass, all 16 datasets
python evaluation/run_all.py --model gemma2:9b       # faster pass
python evaluation/run_all.py --only hdfs,linux,bgl   # a subset

# free cloud Gemma (Google AI Studio) — no local model needed:
export GEMINI_API_KEY=...        # free key: https://aistudio.google.com/apikey
python evaluation/run_all.py --provider google                      # gemma-3-27b-it
python evaluation/run_all.py --provider google --model gemma-4-31b-it
```

Per-dataset JSON is written to `outputs/<dataset>.json` (gitignored). The scorecard
columns: `entries`, `hard` (A–G pass/fail), `recall`, `leak` (benign leakage), `cur`
(curated signatures vs generic). The footer gives hard-pass count, mean recall over
curated datasets, and total leakage.

### Running two models in parallel

To compare e.g. gemma2:9b vs gemma4:12b, each person runs `run_all.py` with a different
`--model` and shares the scorecard (Ollama serializes calls per model, so run them on
separate machines or sequentially). The samples are identical, so the scorecards are
directly comparable.

### Changing the sample size

Samples are reproducible from `data/loghub/` with a fixed seed:

```bash
python evaluation/make_samples.py 300     # default; use 2000 for the full loghub sample
```
