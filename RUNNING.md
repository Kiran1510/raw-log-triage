# Running the Pipeline — Reviewer Guide

Step-by-step instructions to run the log-triage pipeline independently, with **two
interchangeable Gemma backends**: the **Gemini API (cloud, free)** or **local Gemma via
Ollama**. Pick whichever is easier for you — pass `--provider` and everything else is identical.

> **No Python packages to install.** The pipeline uses only the Python 3 standard library.
> You just need Python 3.8+ and *one* Gemma backend below.

---

## 0. Get the code

```bash
git clone https://github.com/Kiran1510/raw-log-triage.git
cd raw-log-triage
python3 --version          # need 3.8+
```

The repo already includes test data: all 16 loghub datasets in `data/loghub/`, plus the full
Linux log in `data/`.

---

## Option A — Cloud Gemma (Gemini API) · easiest, no download

1. Get a **free** API key (no credit card) at <https://aistudio.google.com/apikey>.
2. Export it and run:

```bash
export GEMINI_API_KEY="your-key-here"

python3 pipeline.py data/loghub/HDFS_2k.log -o out.json --provider google
```

- Uses `gemma-4-31b-it` by default. Override with `--model gemma-4-26b-a4b-it`.
- Note: Gemma-4 is a *thinking* model, so each call takes ~40–60s. For a quick taste, run a
  small sample: `python3 pipeline.py data/samples/hdfs.log -o out.json --provider google`.

---

## Option B — Local Gemma (Ollama) · faster per call, runs offline

1. Install Ollama from <https://ollama.com> and make sure it's running (`ollama serve`, or
   just open the Ollama app).
2. Pull a Gemma model and run:

```bash
ollama pull gemma2:9b        # ~5.4 GB, good speed/quality (or: gemma2:2b smaller, gemma4:12b best)

python3 pipeline.py data/loghub/HDFS_2k.log -o out.json --model gemma2:9b
```

- `--provider ollama` is the **default**, so it can be omitted.
- The project's default model is `gemma4:12b`; if you pulled that, you can drop `--model`.

---

## 1. What you'll see

The clean **JSON array** is written to `out.json` and printed to stdout; a human-readable
**report** (profile, counts, timing) is printed to stderr. Example output object:

```json
{
  "service_name": "dfs.DataNode$DataXceiver",
  "timestamp": "081109 214043",
  "error_severity": "warning",
  "suggested_remediation": "Investigate network connectivity or I/O issues for the DataNode.",
  "source_line": "081109 214043 2561 WARN dfs.DataNode$DataXceiver: ...Got exception while serving...",
  "occurrence_count": 36
}
```

## 2. Try unseen formats (it's format-adaptive)

The same command works on any of the 16 datasets — no per-format code:

```bash
python3 pipeline.py data/loghub/Apache_2k.log     -o apache.json --provider google
python3 pipeline.py data/loghub/BGL_2k.log        -o bgl.json    --provider google
python3 pipeline.py data/Linux.log                -o linux.json  --provider google   # full 25k-line file
```

Useful flags: `--no-profile` (skip Stage 1), `--filter` (keyword pre-filter), `--chunk-size N`.

## 3. Run the evaluation (optional)

Score one output against the rubric, or benchmark across all 16 datasets:

```bash
# score a single output
python3 evaluation/eval.py data/loghub/HDFS_2k.log out.json hdfs

# full benchmark → aggregate scorecard (use --provider google or --model <local model>)
python3 evaluation/run_all.py --provider google
python3 evaluation/run_all.py --model gemma2:9b
```

See [evaluation/EVALUATION.md](evaluation/EVALUATION.md) for the rubric and [OVERVIEW.md](OVERVIEW.md)
for the full design.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `GEMINI_API_KEY is not set` | `export GEMINI_API_KEY="..."` (Option A) |
| Cloud: `model ... is not found` (404) | Use `--model gemma-4-31b-it` (the default); `gemma-3-27b-it` is not served |
| Cloud feels slow | Gemma-4 forces "thinking"; use a `data/samples/*.log` file, or switch to local (Option B) |
| Local: `connection refused` / can't reach `localhost:11434` | Start Ollama (`ollama serve` or open the app) |
| Local: model not found | `ollama pull gemma2:9b` (or whatever you pass to `--model`) |
| `CERTIFICATE_VERIFY_FAILED` (cloud, rare) | Handled automatically; if it persists run `pip install certifi` or `export SSL_CERT_FILE=/etc/ssl/cert.pem` |
| Output is `[]` | The log had no detectable errors (e.g. Spark's all-INFO sample) — that's correct behavior |
