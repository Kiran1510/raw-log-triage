# First Pass Evaluation Results (baseline — no prompt fine-tuning)

Snapshot of the **first** benchmark run, **before** any prompt tuning, preserved so we
can measure the before/after of subsequent prompt-engineering changes.

## Configuration

- **Date:** 2026-06-26
- **Backend / model:** local Ollama, `gemma2:9b` (the fast tuning model — *not* the
  judging model `gemma4:12b`)
- **Inputs:** `data/samples/*.log` — 300-line random samples of all 16 loghub datasets
- **Command:** `python evaluation/run_all.py --model gemma2:9b`
- **Pipeline:** two-stage (profile → triage), as of this baseline commit

## Contents

- `outputs/<dataset>.json` — the pipeline's raw output for each of the 16 datasets
- `scorecard.txt` — the aggregate scorecard from `run_all.py`

## Scorecard

```
dataset       entries      hard  recall  leak  cur
------------------------------------------------------------------------------
android             5    FAIL:D   100%     5    y
apache              7      PASS   100%     0    y
bgl                12  FAIL:D,E   100%     4    y
hadoop              3  FAIL:D,E   100%     1    y
hdfs                2      PASS   100%     0    y
healthapp           1      PASS   100%     0    y
hpc                 0      PASS     0%     0    y
linux               6      PASS   100%     0    y
mac                22  FAIL:D,E   100%     0    y
openssh             3      PASS   100%     0    y
openstack           0      PASS     0%     0    y
proxifier          13      PASS   100%     0    y
spark               0      PASS   100%     0    y
thunderbird         7  FAIL:D,E   100%     0    y
windows             3  FAIL:D,E   100%     0    y
zookeeper           3  FAIL:D,E   100%     0    y
------------------------------------------------------------------------------
hard-pass 9/16 | mean recall (curated) 88% | total leakage 10 | 2371s
```

## Interpretation (what to fix in tuning)

- **7 hard failures are mostly `D` (hallucination) + `E` (timestamp)** — `gemma2:9b`
  reformats/garbles `source_line` and timestamps. Largely a weak-model artifact; expected
  to mostly disappear on `gemma4`. A "copy the line verbatim" prompt reinforcement should
  help on 9b too.
- **Benign leakage 10** (android 5, bgl 4, hadoop 1) — INFO/routine lines flagged on
  leveled datasets → strengthen level-awareness. (android's 5 also reflect its
  single-letter `V/D/I` level scheme.)
- **`hpc` / `openstack` recall 0%** — error events missed; investigate (openstack's weak
  dedup + few error-level lines in the 300-sample).
- **`spark` correctly returns `[]`** — the all-INFO precision trap passes.

This is the baseline; re-run after each prompt change and compare against this scorecard.
