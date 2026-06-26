# Evaluation Rubric — Log Triage

> An **approach-agnostic** harness. Any triage approach that emits the output contract
> (a JSON array of objects with the required fields) can be scored — `eval.py` does not
> import the pipeline. Expectations are fixed **before** looking at output, derived from
> the input logs (signature mining in `signatures.py`) and domain knowledge.

## Output contract (what every approach must emit)

A JSON array of objects, each with:
`service_name`, `timestamp`, `error_severity` (∈ {warning, error, fatal}),
`suggested_remediation`, `source_line` (verbatim from input), `occurrence_count` (int ≥ 1).

## How to run

Score one output:

```bash
python evaluation/eval.py <input_log> <output_json> <dataset>
python evaluation/eval.py data/loghub/HDFS_2k.log out.json hdfs
```

Run the reference pipeline over **all 16 loghub datasets** and print an aggregate
scorecard (local Ollama or free cloud Gemma — both use a Gemma model):

```bash
python evaluation/run_all.py --model gemma4:12b      # local, full quality
python evaluation/run_all.py --model gemma2:9b       # local, faster
export GEMINI_API_KEY=...                            # free: aistudio.google.com/apikey
python evaluation/run_all.py --provider google       # cloud gemma-4-31b-it
```

`<dataset>` selects ground-truth signatures from `signatures.py`. Unknown datasets fall
back to a generic set (approximate). See [README.md](README.md) for full usage.

## Checks

| # | Check | Type | Pass condition |
|---|-------|------|----------------|
| A | JSON validity | hard | Parses as a JSON array |
| B | Schema completeness | hard | Every object has all 6 contract fields |
| C | Severity validity | hard | `error_severity` ∈ {warning, error, fatal} |
| D | No hallucination | hard | Every `source_line` exists in the input (whitespace-insensitive; pure reformatting is reported separately, not failed) |
| E | Timestamp fidelity | hard | `timestamp` is a substring of its `source_line` (or empty) |
| F | Dedup | hard | No duplicate `(service_name, timestamp, source_line)` |
| G | occurrence_count sane | hard | Each ≥ 1; **sum ≤ input line count** (fabrication guard) |
| H | Recall | soft | Each *present* error signature is covered by ≥1 output entry |
| I | Benign leakage | soft | No output entry matches a benign signature (want 0) |
| i | Count cross-check | info | `occurrence_count` vs an independent recount |
| J | Remediation non-trivial | soft | `suggested_remediation` is specific/actionable |

Headline metrics: **Recall**, **Benign leakage**, and pass/fail on A–G.

## Ground-truth strategy (`signatures.py`)

Two ways to define truth, chosen per dataset:

- **Level-based** — the log has an explicit severity field, so `error` = WARN/ERROR/FATAL
  and `benign` = INFO/DEBUG. Used for: **HDFS, BGL, Hadoop, OpenStack, Spark, Zookeeper,
  Android** (single-letter `V/D/I` vs `W/E/F`), **Windows** (`Info`/`Warning`/`Error`).
  This directly tests the pipeline's level-awareness.
- **Keyword-based** — curated phrase regexes. Used for: **Apache** (`[error]` vs
  `[notice]`), **HPC, HealthApp, Linux, Mac, OpenSSH, Proxifier, Thunderbird**.
- **DEFAULT** — generic error/benign keywords for any dataset without a curated entry.

### Dataset overview (loghub 2k samples)

Template counts after dedup vary widely — a few datasets saturate fast, others stay
diverse (and OpenStack's UUIDs/request-ids defeat the current masking):

| low-diversity | mid | high-diversity |
|---|---|---|
| Apache 12, Spark 40, HDFS 41, Zookeeper 60 | HPC 73, Windows 75, HealthApp 75, Hadoop 138, Linux 148 | Android 186, OpenSSH 186, Thunderbird 261, Mac 404, BGL 466, Proxifier 544, **OpenStack 1500** |

## Per-dataset expectations (curated)

**Linux.log** — must cover: `authentication failure` (dominant), `Out of Memory / Killed
process`, `ALERT exited abnormally`, `ttloop: peer died`, `page allocation failure`,
`Kerberos authentication fail`, `gethostbyname error`, `register_security failed`,
`Failure registering capabilities`, `Invalid ACPI-PCI IRQ routing table`, `cdrom: open
failed`, `bind failed`/`Service telnet failed`, `mdmpd failed`, `recovery required on
readonly filesystem`, `couldn't add command channel`. Must NOT flag: `startup succeeded`,
`session opened/closed`, `Linux version`, `Kernel command line`, `BIOS-e820`.

**HDFS_2k.log** — must cover `Got exception while serving` (DataXceiver WARN). Must NOT
flag routine INFO ops (`PacketResponder … terminating`, `blockMap updated`, `NameSystem.
delete`/`invalidSet`). Severity maps from `WARN` → `warning`; exception family count ≈ 80.

## Results

### Cross-dataset baseline — `gemma2:9b`, 300-line samples (pre-tuning)

Preserved in [`../results/`](../results/). **9/16 hard-pass · 88% mean recall (curated) ·
10 benign leakage.** Failures were mostly `gemma2:9b` hallucination/timestamp sloppiness
(`D`/`E`) on android/bgl/hadoop/mac/thunderbird/windows/zookeeper, plus benign leakage on
the leveled datasets (android 5, bgl 4, hadoop 1). Spark correctly returned `[]`.

### Tuning iteration 1 (verbatim source_line, timestamp-as-substring, single-letter levels)
### + cloud `gemma-4-31b-it`

_(scorecard added when the cloud pass completes; early datasets show the `D`/`E` failures
clearing and android leakage dropping 5 → 1.)_

### HDFS — precision fix (before vs. after level-awareness / anti-keyword-trap)

| Metric | Baseline | After |
|---|---|---|
| Entries | 4 | 2 |
| **Benign leakage** | 2 (`NameSystem.delete … invalidSet`) | **0** |
| Recall | 100% | 100% |

### Linux.log — full 25,567 lines (gemma4:12b)

728 templates (from 1,116) → 531 after benign filter; 11 calls; 1,402 s; 75 entries
(22 fatal / 15 error / 38 warning). Hard checks **PASS**, benign leakage **0**, recall
**53%** — the precision changes made it over-conservative on borderline boot/kernel errors
(open tuning target).

## Limitations

- Recall/precision are **signature proxies** — only as good as `signatures.py`; level-based
  truth assumes the log's own level field is correct (e.g. Windows logs some failures at
  `Info`, which we treat as benign).
- 300-line samples **under-cover** high-diversity datasets — fine for comparing prompt
  versions, not for absolute recall. The hard checks (A–G) are exact and model-independent.
