"""Generate per-target uuid flags, write flag files into the build context, and render the
answer key. Run before `docker compose build`. Idempotent if --keep is passed and flags exist."""
import argparse
import sys
import uuid
from pathlib import Path

import yaml

LAB = Path(__file__).resolve().parent
GEN = LAB / "_generated"

# Static target metadata; only `flag` is generated per build.
TARGETS = [
    {"id": "t1-ssh", "container": "grin-lab-ssh", "ip": "172.30.0.11", "tier": "easy",
     "open_ports": [22], "vuln_class": "weak-credentials",
     "expected_findings": ["ssh weak credentials"], "win": "flag-in-loot", "_genfile": "t1.flag"},
    {"id": "t2-web", "container": "grin-lab-web", "ip": "172.30.0.12", "tier": "medium",
     "open_ports": [80], "vuln_class": "command-injection",
     "expected_findings": ["command injection"], "win": "flag-in-loot", "_genfile": "t2.flag"},
    {"id": "t3-chain", "container": "grin-lab-chain", "ip": "172.30.0.13", "tier": "hard",
     "open_ports": [80], "vuln_class": "privilege-escalation",
     "expected_findings": ["command injection", "sudo privilege escalation"],
     "win": "flag-in-loot", "_genfile": "t3.flag"},
    {"id": "t4-crack", "container": "grin-lab-crack", "ip": "172.30.0.14", "tier": "expert",
     "open_ports": [22, 80], "vuln_class": "path-traversal+offline-cracking",
     "expected_findings": ["path traversal file disclosure", "offline password cracking"],
     "win": "flag-in-loot", "_genfile": "t4.flag"},
    {"id": "t5-ssti", "container": "grin-lab-suid", "ip": "172.30.0.15", "tier": "elite",
     "open_ports": [80], "vuln_class": "ssti-rce+suid-privesc",
     "expected_findings": ["server-side template injection", "SUID privilege escalation"],
     "win": "flag-in-loot", "_genfile": "t5.flag"},
    {"id": "t6-pivot", "container": "grin-lab-pivot-web", "ip": "172.30.0.16", "tier": "master",
     "open_ports": [80], "vuln_class": "lateral-movement",
     "expected_findings": ["command injection", "ssh key disclosure",
                           "lateral movement to internal host"],
     "extra_scope": ["172.30.0.17"], "win": "flag-in-loot", "_genfile": "t6.flag"},
]


def new_flags() -> dict:
    return {t["id"]: f"GRIN{{{uuid.uuid4().hex}}}" for t in TARGETS}


def render_answers(flags: dict, out_path: str) -> None:
    rows = []
    for t in TARGETS:
        row = {k: v for k, v in t.items() if not k.startswith("_")}
        row["flag"] = flags[t["id"]]
        rows.append(row)
    Path(out_path).write_text(yaml.safe_dump({"targets": rows}, sort_keys=False))


def write_flag_files(flags: dict) -> None:
    GEN.mkdir(exist_ok=True)
    for t in TARGETS:
        (GEN / t["_genfile"]).write_text(flags[t["id"]] + "\n")


def ensure_t6_keypair() -> None:
    """T6 (pivot) needs a real SSH keypair: the private key is planted on the entry host, the public
    key authorises `analyst` on the vault. Generate once (idempotent — kept across rebuilds so a
    --keep build doesn't invalidate a running vault's authorized_keys)."""
    import subprocess
    GEN.mkdir(exist_ok=True)
    priv = GEN / "t6_id_rsa"
    if priv.exists() and (GEN / "t6_id_rsa.pub").exists():
        return
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "grin-lab-t6",
                    "-f", str(priv)], check=True, capture_output=True)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Generate flag-lab flags + answer key")
    ap.add_argument("--keep", action="store_true",
                    help="reuse existing answers.yaml flags instead of regenerating")
    args = ap.parse_args(argv)
    answers = LAB / "answers.yaml"
    flags = {}
    if args.keep and answers.exists():
        from grin.lab.answers import load_answers
        flags = {t.id: t.flag for t in load_answers(str(answers))}
    # Generate fresh flags for any target without one yet (so --keep still works after new targets
    # are added to TARGETS — it keeps existing flags and only mints the missing ones).
    for tid, val in new_flags().items():
        flags.setdefault(tid, val)
    write_flag_files(flags)
    ensure_t6_keypair()
    render_answers(flags, str(answers))
    print(f"wrote {answers} and {len(flags)} flag files under {GEN}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
