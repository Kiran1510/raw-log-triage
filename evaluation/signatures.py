"""Ground-truth signatures per dataset, used by eval.py.

Each entry is keyed by a short dataset name (matched case-insensitively against the
3rd CLI arg of eval.py). For every dataset:

  "error"  : regexes that, IF present in the input log, MUST be surfaced in the output
             (recall targets).
  "benign" : regexes that MUST NOT appear in the output (precision / false-positive
             targets).

To add a new loghub dataset (Apache, BGL, Spark, Zookeeper, ...), copy an entry, set
the recall targets (the genuinely-bad events) and benign targets (routine noise that
looks error-ish), and you are done. Datasets with no entry fall back to DEFAULT.
"""

SIGNATURES = {
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
        "benign": [
            "startup succeeded", "session opened", "session closed",
            "Linux version", "Kernel command line", "BIOS-e820",
        ],
    },
    "hdfs": {
        "error": ["Got exception while serving"],
        "benign": [
            "Verification succeeded for", "blockMap updated", "Receiving block",
            "Received block", r"PacketResponder.*terminating",
            r"NameSystem\.delete|added to invalidSet",  # routine block GC
            "NameSystem.addStoredBlock",
        ],
    },
}

# Generic fallback for datasets without curated signatures (rough recall/precision).
DEFAULT = {
    "error": [
        r"\b(error|fail|failed|failure|exception|panic|fatal|denied|timed?\s*out|"
        r"refused|unable|cannot|corrupt|aborted?|segfault)\b",
    ],
    "benign": [
        r"\b(started|startup succeeded|stopped|listening|established|"
        r"session opened|session closed)\b",
    ],
}


def get_signatures(dataset: str) -> dict:
    return SIGNATURES.get(dataset.lower(), DEFAULT)


def is_curated(dataset: str) -> bool:
    return dataset.lower() in SIGNATURES
