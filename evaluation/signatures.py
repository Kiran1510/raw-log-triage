"""Ground-truth signatures per dataset, used by eval.py.

Each entry, keyed by lowercase dataset name:
  "error"  : regexes that, IF present in the input, MUST be surfaced (recall targets).
  "benign" : regexes that MUST NOT appear in the output (precision targets).

Two strategies are used:
  * LEVELED logs (HDFS, BGL, Hadoop, OpenStack, Spark, Zookeeper, Android, Windows):
    ground truth derived from the explicit level field — error = WARN/ERROR/FATAL,
    benign = INFO/DEBUG. This directly tests the pipeline's level-awareness.
  * UNLEVELED logs (Apache, HPC, HealthApp, Linux, Mac, OpenSSH, Proxifier,
    Thunderbird): curated keyword signatures.

Datasets with no entry fall back to DEFAULT (approximate). To add one, copy an entry.
"""

SIGNATURES = {
    # ---- leveled: ground truth from the level field ------------------------------
    "hdfs": {  # curated (more specific than bare level words)
        "error": ["Got exception while serving"],
        "benign": [
            "Verification succeeded for", "blockMap updated", "Receiving block",
            "Received block", r"PacketResponder.*terminating",
            r"NameSystem\.delete|added to invalidSet", "NameSystem.addStoredBlock",
        ],
    },
    "bgl":       {"error": [r"\b(WARNING|ERROR|FATAL|SEVERE|FAILURE)\b"], "benign": [r"\bINFO\b"]},
    "hadoop":    {"error": [r"\b(WARN|ERROR|FATAL)\b"],                   "benign": [r"\bINFO\b"]},
    "openstack": {"error": [r"\b(WARNING|ERROR)\b"],                      "benign": [r"\bINFO\b"]},
    "spark":     {"error": [r"\b(WARN|ERROR|FATAL)\b"],                   "benign": [r"\bINFO\b"]},
    "zookeeper": {"error": [r"\b(WARN|ERROR|FATAL)\b"],                   "benign": [r"\bINFO\b"]},
    "android":   {"error": [r"\s\d+\s+\d+\s+[WEF]\s"],                    "benign": [r"\s\d+\s+\d+\s+[VDI]\s"]},
    "windows":   {"error": [r",\s+(Warning|Error)\b"],                    "benign": [r",\s+Info\b"]},

    # ---- unleveled: curated keyword signatures -----------------------------------
    "linux": {
        "error": [
            "authentication failure", "ALERT exited abnormally",
            r"ttloop: peer died|Invalid or incomplete multibyte",
            r"Out of Memory|Killed process",
            "page allocation failure", "Kerberos authentication fail",
            "gethostbyname error", "register_security failed",
            "Failure registering capabilities", "Invalid ACPI-PCI IRQ routing table",
            "cdrom: open failed", r"bind failed|Service telnet failed",
            "mdmpd failed", "recovery required on readonly filesystem",
            "couldn't add command channel",
        ],
        "benign": ["startup succeeded", "session opened", "session closed",
                   "Linux version", "Kernel command line", "BIOS-e820"],
    },
    "apache": {
        "error": [r"\[error\]|\[crit\]|\[alert\]|\[emerg\]"],
        "benign": [r"\[notice\]|\[info\]|\[debug\]"],
    },
    "hpc": {
        "error": [r"unavailable|\bhalt|error|fail|fatal|critical|fault|\bdown\b"],
        "benign": [r"running|configured in|\bavailable\b|\bup\b"],
    },
    "healthapp": {
        "error": [r"\bfail|error|exception|crash|\banr\b|cannot|unable"],
        "benign": [r"onStandStepChanged|setStepCount|onReceive|onExtend"],
    },
    "mac": {
        "error": [r"\berror\b|\bfailed\b|\bfailure\b|panic|\bcannot\b|\bunable\b|"
                  r"denied|timed out|exception|fault"],
        "benign": [],
    },
    "openssh": {
        "error": [r"Failed password|authentication failure|[Ii]nvalid user|error:|"
                  r"Did not receive identification|POSSIBLE BREAK-IN|"
                  r"Bad protocol version|maximum authentication attempts"],
        "benign": [r"Accepted password|session opened|session closed|Connection from"],
    },
    "proxifier": {
        "error": [r"error :|[Cc]ould not connect|failed|timed out|cannot"],
        "benign": [r"open through proxy|close, \d|opening "],
    },
    "thunderbird": {
        "error": [r"unable to|error|fail|fatal|panic|cannot|denied|refused|timed out"],
        "benign": [],
    },
}

DEFAULT = {
    "error": [r"\b(error|fail|failed|failure|exception|panic|fatal|denied|timed?\s*out|"
              r"refused|unable|cannot|corrupt|aborted?|segfault)\b"],
    "benign": [r"\b(started|startup succeeded|stopped|listening|established|"
               r"session opened|session closed)\b"],
}


def get_signatures(dataset: str) -> dict:
    return SIGNATURES.get(dataset.lower(), DEFAULT)


def is_curated(dataset: str) -> bool:
    return dataset.lower() in SIGNATURES
