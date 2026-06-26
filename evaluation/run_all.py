"""Run the pipeline on every sample in data/samples/ and score each, then print an
aggregate scorecard. This is the tuning-loop driver.

Usage:
    python evaluation/run_all.py [--model gemma2:9b] [--samples-dir data/samples]
                                 [--chunk-size 50] [--only linux,hdfs]

Outputs go to outputs/<dataset>.json (gitignored). The approach is invoked as a
subprocess (pipeline.py), so it could be swapped for any tool that honors the contract.
"""
import argparse
import glob
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from eval import evaluate

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="gemma2:9b")
    ap.add_argument("--samples-dir", default="data/samples")
    ap.add_argument("--chunk-size", type=int, default=50)
    ap.add_argument("--outputs-dir", default="outputs")
    ap.add_argument("--only", default="", help="comma-separated dataset subset")
    args = ap.parse_args()

    os.makedirs(args.outputs_dir, exist_ok=True)
    only = {s.strip() for s in args.only.split(",") if s.strip()}
    samples = sorted(glob.glob(os.path.join(args.samples_dir, "*.log")))

    rows, t0 = [], time.time()
    for sp in samples:
        ds = os.path.basename(sp).replace(".log", "")
        if only and ds not in only:
            continue
        out = os.path.join(args.outputs_dir, f"{ds}.json")
        print(f"\n### {ds} (model={args.model}) ###", flush=True)
        r = subprocess.run(
            [sys.executable, "pipeline.py", sp, "-o", out,
             "--model", args.model, "--chunk-size", str(args.chunk_size)],
            cwd=REPO, capture_output=True, text=True)
        if r.returncode != 0:
            print(f"  pipeline FAILED: {r.stderr[-300:]}")
            rows.append({"dataset": ds, "entries": "ERR", "hard_pass": False,
                         "recall": 0, "leakage": "-", "curated": False})
            continue
        res = evaluate(sp, out, ds, verbose=False)
        rows.append(res)
        print(f"  entries={res['entries']} hard={'OK' if res['hard_pass'] else res['failures']} "
              f"recall={res['recall']:.0%} leakage={res['leakage']} "
              f"sev={res.get('severities', {})}")

    # Aggregate scorecard
    print("\n" + "=" * 78)
    print(f"{'dataset':<13}{'entries':>8}{'hard':>10}{'recall':>8}{'leak':>6}{'cur':>5}")
    print("-" * 78)
    hard_ok = rec_sum = rec_n = 0
    for r in rows:
        hp = "PASS" if r["hard_pass"] else "FAIL:" + ",".join(r.get("failures", []))
        rec = r["recall"]
        print(f"{r['dataset']:<13}{str(r['entries']):>8}{hp:>10}{rec:>7.0%}"
              f"{str(r['leakage']):>6}{'y' if r.get('curated') else 'n':>5}")
        hard_ok += 1 if r["hard_pass"] else 0
        if r.get("curated"):
            rec_sum += rec
            rec_n += 1
    print("-" * 78)
    print(f"hard-pass {hard_ok}/{len(rows)} | mean recall (curated) "
          f"{rec_sum / rec_n if rec_n else 0:.0%} | "
          f"total leakage {sum(r['leakage'] for r in rows if isinstance(r['leakage'], int))} | "
          f"{time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
