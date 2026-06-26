"""Create small, reproducible evaluation samples from the loghub 2k logs.

Usage: python evaluation/make_samples.py [N]   (default N=300)

Writes data/samples/<dataset>.log = N lines randomly sampled (fixed seed, order
preserved) from each data/loghub/<Dataset>_2k.log. Random (not head) so the sample
captures error diversity rather than just the early/boot region.
"""
import glob
import os
import random
import sys

SRC, DST = "data/loghub", "data/samples"
N = int(sys.argv[1]) if len(sys.argv) > 1 else 300
random.seed(0)

os.makedirs(DST, exist_ok=True)
for fn in sorted(glob.glob(f"{SRC}/*_2k.log")):
    name = os.path.basename(fn).replace("_2k.log", "").lower()
    lines = [l for l in open(fn, errors="ignore") if l.strip()]
    idx = sorted(random.sample(range(len(lines)), min(N, len(lines))))
    with open(f"{DST}/{name}.log", "w") as out:
        out.writelines(lines[i] for i in idx)
    print(f"{name:<14} {len(idx)} lines")
