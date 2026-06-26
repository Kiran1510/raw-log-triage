"""Approach-agnostic evaluator for log-triage outputs.

Usage:
    python evaluation/eval.py <input_log> <output_json> <dataset>

Scores ANY approach's output JSON (it does not import the pipeline). The only contract
is a JSON array of objects with the required fields. Exit code is non-zero if any hard
check (A-G) fails. See EVALUATION.md for the rubric, signatures.py for ground truth.
"""
import json
import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from signatures import get_signatures, is_curated

REQUIRED = {"service_name", "timestamp", "error_severity",
            "suggested_remediation", "source_line", "occurrence_count"}
VALID_SEV = {"warning", "error", "fatal"}

# Independent normalizer for the occurrence-count cross-check.
_PID = re.compile(r"\[\d+\]")
_KV = re.compile(r"([A-Za-z_][\w-]*)=\S+")
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_NUM = re.compile(r"\d+")
_WS = re.compile(r"\s+")
_SYSLOG = re.compile(r"^[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+\S+\s+(?P<body>.*)$")


def _ws(s: str) -> str:
    return _WS.sub(" ", str(s)).strip()


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


def evaluate(log_path: str, out_path: str, dataset: str, verbose: bool = True) -> dict:
    sig = get_signatures(dataset)
    with open(log_path, errors="ignore") as f:
        lines = [l.rstrip("\n") for l in f]
    line_set = set(lines)
    ws_set = {_ws(l) for l in lines}                 # whitespace-insensitive membership
    input_text = "\n".join(lines)
    nonempty = sum(1 for l in lines if l.strip())
    norm_counts = Counter(normalize(l) for l in lines if l.strip())

    out = {"dataset": dataset, "failures": [], "curated": is_curated(dataset)}
    log = (lambda *a: print(*a)) if verbose else (lambda *a: None)

    def check(tag, name, cond, detail=""):
        log(f"[{tag}] {name:<30}: {'PASS' if cond else 'FAIL — ' + detail}")
        if not cond:
            out["failures"].append(tag)

    try:
        with open(out_path) as f:
            data = json.load(f)
        assert isinstance(data, list)
    except Exception as e:
        log(f"[A] JSON validity                 : FAIL ({e})")
        out.update(entries=0, hard_pass=False, recall=0.0, leakage=0)
        out["failures"].append("A")
        return out
    log(f"[A] JSON validity                 : PASS ({len(data)} entries)")
    out["entries"] = len(data)

    check("B", "Schema completeness",
          all(isinstance(e, dict) and REQUIRED <= set(e) for e in data),
          f"{sum(1 for e in data if not (isinstance(e, dict) and REQUIRED <= set(e)))} bad")
    bad_sev = {e.get("error_severity") for e in data if e.get("error_severity") not in VALID_SEV}
    check("C", "Severity validity", not bad_sev, f"invalid: {bad_sev}")

    out_lines = [str(e.get("source_line", "")) for e in data]
    # D: true hallucination = absent even after collapsing internal whitespace.
    halluc = [sl for sl in out_lines if _ws(sl) not in ws_set]
    reformatted = sum(1 for sl in out_lines if sl not in line_set and _ws(sl) in ws_set)
    check("D", "No hallucinated source_line", not halluc,
          f"{len(halluc)} absent; e.g. {halluc[:1]}")
    out["reformatted"] = reformatted

    bad_ts = [e for e in data if e.get("timestamp") and e["timestamp"] not in str(e.get("source_line"))]
    check("E", "Timestamp subset of source_line", not bad_ts, f"{len(bad_ts)} bad")
    tuples = [(e.get("service_name"), e.get("timestamp"), e.get("source_line")) for e in data]
    check("F", "No duplicate entries", len(tuples) == len(set(tuples)),
          f"{len(tuples) - len(set(tuples))} dups")
    counts = [e.get("occurrence_count") for e in data]
    total = sum(c for c in counts if isinstance(c, int))
    check("G", "occurrence_count sane",
          all(isinstance(c, int) and c >= 1 for c in counts) and total <= nonempty,
          f"sum={total} > {nonempty}")

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

    # I. Benign leakage (soft)
    leaks = []
    for pat in sig["benign"]:
        rx = re.compile(pat, re.IGNORECASE)
        leaks += [(pat, sl[:70]) for sl in out_lines if rx.search(sl)]

    matched = sum(1 for e in data
                  if norm_counts.get(normalize(str(e.get("source_line", "")))) == e.get("occurrence_count"))

    out.update(hard_pass=not out["failures"], recall=recall, present=present,
               covered=covered, missed=missed, leakage=len(leaks),
               severities=dict(Counter(e.get("error_severity") for e in data)),
               count_match=f"{matched}/{len(data)}")

    if verbose:
        log(f"[H] Recall                        : {covered}/{present} = {recall:.0%}"
            + (f"  MISSED: {missed}" if missed else ""))
        log(f"[I] Benign leakage                : {len(leaks)} (want 0)")
        for pat, sl in leaks[:5]:
            log(f"    LEAK [{pat}]: {sl}")
        log(f"[i] occurrence_count vs recount   : {matched}/{len(data)} exact"
            + (f"   (+{reformatted} whitespace-reformatted)" if reformatted else ""))
        log(f"    Severity: {out['severities']}")
        log(f"\n=== HARD CHECKS A-G: {'ALL PASS' if out['hard_pass'] else 'FAILED ' + str(out['failures'])}")
        log(f"=== Recall {recall:.0%} | Benign leakage {len(leaks)} | Entries {len(data)}")
    return out


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(2)
    log_path, out_path, dataset = sys.argv[1:4]
    if not is_curated(dataset):
        print(f"NOTE: no curated signatures for '{dataset}'; using generic DEFAULT.\n")
    print(f"=== Evaluating {out_path} on {log_path} (dataset='{dataset}') ===")
    res = evaluate(log_path, out_path, dataset, verbose=True)
    sys.exit(0 if res.get("hard_pass") else 1)


if __name__ == "__main__":
    main()
