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

```
python evaluation/eval.py <input_log> <output_json> <dataset>
# e.g.
python evaluation/eval.py data/Linux.log my_output.json linux
python evaluation/eval.py data/HDFS_2k.log my_output.json hdfs
```

`<dataset>` selects ground-truth signatures from `signatures.py`. Unknown datasets fall
back to a generic signature set (approximate). To add a loghub dataset, add an entry to
`signatures.py`.

## Checks

| # | Check | Type | Pass condition |
|---|-------|------|----------------|
| A | JSON validity | hard | Parses as a JSON array |
| B | Schema completeness | hard | Every object has all 6 contract fields |
| C | Severity validity | hard | `error_severity` ∈ {warning, error, fatal} |
| D | No hallucination | hard | Every `source_line` exists verbatim in the input |
| E | Timestamp fidelity | hard | `timestamp` is a substring of its `source_line` (or empty) |
| F | Dedup | hard | No duplicate `(service_name, timestamp, source_line)` |
| G | occurrence_count sane | hard | Each ≥ 1; **sum ≤ input line count** (fabrication guard) |
| H | Recall | soft | Each *present* error signature is covered by ≥1 output entry |
| I | Benign leakage | soft | No output entry matches a benign signature (want 0) |
| i | Count cross-check | info | `occurrence_count` vs an independent recount |
| J | Remediation non-trivial | soft | `suggested_remediation` is specific/actionable |

Headline metrics: **Recall**, **Benign leakage**, and pass/fail on A–G.

## Expectations — Linux.log (25,567 lines)

**Must be covered (recall):** `authentication failure` (dominant), `Out of Memory / Killed
process`, `ALERT exited abnormally` (logrotate), `ttloop: peer died` (telnetd), `page
allocation failure` (httpd), `Kerberos authentication fail`, `gethostbyname error`
(format-string attack), `register_security failed`, `Failure registering capabilities`,
`Invalid ACPI-PCI IRQ routing table`, `cdrom: open failed`, `bind failed` / `Service
telnet failed` (xinetd), `mdmpd failed`, `recovery required on readonly filesystem`,
`couldn't add command channel`.

**Must NOT appear (precision):** `startup succeeded`, `session opened/closed`,
`Linux version`, `Kernel command line`, `BIOS-e820`.

## Expectations — HDFS_2k.log (2,000 lines)

**Must be covered:** `Got exception while serving` (DataXceiver WARN; only non-INFO family).
**Must NOT appear:** routine INFO ops — `PacketResponder … terminating`, `blockMap updated`,
`Receiving/Received block`, `verification succeeded`, `NameSystem.delete`/`invalidSet`.
**Other:** severity should map from explicit `WARN` → `warning`; exception family
`occurrence_count` should total ≈ 80.

## Results

### HDFS_2k.log — before vs. after the precision improvements

| Metric | Baseline | + level-awareness / anti-keyword-trap |
|---|---|---|
| Entries | 4 | 2 |
| **Benign leakage** | 2 (`NameSystem.delete … invalidSet` flagged) | **0** |
| Recall | 100% | 100% |
| Hard checks A–G | PASS | PASS |

The two false positives (routine INFO block GC) were eliminated with no recall loss by
teaching Stage 2 to trust explicit log levels and not flag on keyword presence inside
routine identifiers.

### Linux.log — full 25,567 lines (gemma4:12b, two-stage)

| Metric | Value |
|---|---|
| Templates after dedup masking | 728 (from 1,116) → 531 after benign filter |
| Model calls | 11 | Wall-clock | 1,402 s |
| Entries | 75 (22 fatal / 15 error / 38 warning) |
| Hard checks A–G | **PASS** (0 hallucinations; 11 whitespace-reformatted lines handled by the evaluator) |
| Benign leakage | 0 |
| **Recall** | **53%** (8/15 signatures) |

**Finding:** the precision-focused prompt changes (level-awareness + anti-keyword-trap)
made the model **over-conservative on Linux**, missing borderline boot/kernel errors
(`ALERT exited abnormally`, ACPI IRQ table, `mdmpd failed`, EXT3 recovery, …). Recall is
the open tuning target — to be balanced via the cross-dataset loop without re-introducing
the HDFS false positives.

## Cross-dataset benchmark

All 16 loghub datasets are scored uniformly via `run_all.py` on 300-line samples; see the
generated scorecard. Spark (all-INFO) is a precision trap — the correct output is `[]`,
which the level-aware pipeline produces. OpenStack exposes a dedup weakness (UUIDs/request
IDs aren't masked → ~1,500 templates from 2,000 lines), a known tuning target.
