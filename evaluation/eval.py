"""Approach-agnostic evaluator for log-triage outputs.

Usage:
    python evaluation/eval.py <input_log> <output_json> <dataset>

It scores ANY approach's output (not just ours): the only contract is that
<output_json> is a JSON array of objects with the required fields below. It does
not import the pipeline, so a collaborator's tool is judged purely on its output.

Exit code is non-zero if any hard check (A-G) fails.
See EVALUATION.md for the rubric and signatures.py for per-dataset ground truth.
"""
import json
import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from signatures import get_signatures, is_curated

# The output contract every approach must satisfy.
REQUIRED = {"service_name", "timestamp", "error_severity",
            "suggested_remediation", "source_line", "occurrence_count"}
VALID_SEV = {"warning", "error", "fatal"}

# Independent normalizer for the occurrence-count cross-check (no dependency on any
# approach's dedup logic). Masks the variable parts of a line so repeats collapse.
_PID = re.compile(r"\[\d+\]")
_KV = re.compile(r"([A-Za-z_][\w-]*)=\S+")
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_NUM = re.compile(r"\d+")
_WS = re.compile(r"\s+")
_SYSLOG = re.compile(r"^[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+\S+\s+(?P<body>.*)$")


def normalize(line: str) -> str:
    text = line.strip()
    m = _SYSLOG.match(text)
    if m:
        text = m.group("body")
    text = _PID.sub("[]", text)
    text = _KV.sub(r"\1=#", text)
    text = _IP.sub("#", text)
    text = _NUM.sub("#", text)
    return _WS.sub(" ", text).strip()


def ok(failures, tag, name, cond, detail=""):
    print(f"[{tag}] {name:<30}: {'PASS' if cond else 'FAIL — ' + detail}")
    if not cond:
        failures.append(tag)


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(2)
    log_path, out_path, dataset = sys.argv[1], sys.argv[2], sys.argv[3]
    sig = get_signatures(dataset)
    if not is_curated(dataset):
        print(f"NOTE: no curated signatures for '{dataset}'; using generic DEFAULT "
              f"(recall/precision are approximate).\n")

    with open(log_path, errors="ignore") as f:
        lines = [l.rstrip("\n") for l in f]
    line_set = set(lines)
    stripped_set = {l.strip() for l in lines}
    input_text = "\n".join(lines)
    nonempty = sum(1 for l in lines if l.strip())
    norm_counts = Counter(normalize(l) for l in lines if l.strip())

    print(f"=== Evaluating {out_path} on {log_path} (dataset='{dataset}') ===")
    failures = []

    # A. JSON validity
    try:
        with open(out_path) as f:
            data = json.load(f)
        assert isinstance(data, list)
        print(f"[A] JSON validity                 : PASS ({len(data)} entries)")
    except Exception as e:
        print(f"[A] JSON validity                 : FAIL ({e})")
        sys.exit(1)

    # B. Schema completeness
    bad = [i for i, e in enumerate(data) if not (isinstance(e, dict) and REQUIRED <= set(e))]
    ok(failures, "B", "Schema completeness", not bad, f"{len(bad)} objects missing keys")

    # C. Severity validity
    bad_sev = {e.get("error_severity") for e in data
               if e.get("error_severity") not in VALID_SEV}
    ok(failures, "C", "Severity validity", not bad_sev, f"invalid: {bad_sev}")

    # D. No hallucination (source_line verbatim in input)
    halluc = [e["source_line"] for e in data
              if e.get("source_line") not in line_set
              and str(e.get("source_line")).strip() not in stripped_set]
    ok(failures, "D", "No hallucinated source_line", not halluc,
       f"{len(halluc)} not in input; e.g. {halluc[:1]}")

    # E. Timestamp fidelity
    bad_ts = [e for e in data
              if e.get("timestamp") and e["timestamp"] not in str(e.get("source_line"))]
    ok(failures, "E", "Timestamp subset of source_line", not bad_ts,
       f"{len(bad_ts)} not substrings")

    # F. Dedup
    tuples = [(e.get("service_name"), e.get("timestamp"), e.get("source_line")) for e in data]
    dups = len(tuples) - len(set(tuples))
    ok(failures, "F", "No duplicate entries", dups == 0, f"{dups} duplicates")

    # G. Occurrence-count fabrication guard (approach-agnostic)
    counts = [e.get("occurrence_count") for e in data]
    bad_counts = [c for c in counts if not isinstance(c, int) or c < 1]
    total_claimed = sum(c for c in counts if isinstance(c, int))
    ok(failures, "G", "occurrence_count sane", not bad_counts and total_claimed <= nonempty,
       f"{len(bad_counts)} invalid; sum={total_claimed} > {nonempty} lines"
       if (bad_counts or total_claimed > nonempty) else "")

    out_lines = [str(e.get("source_line", "")) for e in data]

    # H. Recall (soft)
    present, covered, missed = 0, 0, []
    for pat in sig["error"]:
        rx = re.compile(pat, re.IGNORECASE)
        if rx.search(input_text):
            present += 1
            if any(rx.search(sl) for sl in out_lines):
                covered += 1
            else:
                missed.append(pat)
    recall = covered / present if present else 1.0
    print(f"[H] Recall                        : {covered}/{present} present "
          f"signatures = {recall:.0%}")
    if missed:
        print(f"    MISSED: {missed}")

    # I. Precision / benign leakage (soft)
    leaks = []
    for pat in sig["benign"]:
        rx = re.compile(pat, re.IGNORECASE)
        for sl in out_lines:
            if rx.search(sl):
                leaks.append((pat, sl[:70]))
    print(f"[I] Benign leakage                : {len(leaks)} (want 0)")
    for pat, sl in leaks[:5]:
        print(f"    LEAK [{pat}]: {sl}")

    # Informational: how well occurrence_count matches an independent recount.
    matched = sum(1 for e in data
                  if norm_counts.get(normalize(str(e.get("source_line", "")))) == e.get("occurrence_count"))
    print(f"[i] occurrence_count vs independent recount: {matched}/{len(data)} exact")

    # J. Remediation non-trivial (soft)
    weak = [e for e in data if len(str(e.get("suggested_remediation", "")).strip()) < 15]
    print(f"[J] Remediation non-trivial       : {len(data) - len(weak)}/{len(data)}")
    print("    Severity breakdown:", dict(Counter(e.get("error_severity") for e in data)))

    print(f"\n=== HARD CHECKS (A-G): {'ALL PASS' if not failures else 'FAILED ' + str(failures)}")
    print(f"=== Recall {recall:.0%} | Benign leakage {len(leaks)} | Entries {len(data)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
