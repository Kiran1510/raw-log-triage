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
