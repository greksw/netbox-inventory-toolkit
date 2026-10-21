#!/usr/bin/env python3
"""Run the local RouterOS IPAM audit once and publish textfile metrics.

Only the dedicated netbox-routeros-ipam.prom file is atomically replaced.
No direct router/NetBox writes, Prometheus config edits, or service restarts.
Audit stdout is parsed but never relayed, preventing disclosure of IPAM data.
Exit codes: 0=CLEAN, 1=DRIFT, 2=ERROR.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

FILE_NAME = "netbox-routeros-ipam.prom"
COUNTS = {
    "routeros_vlans": "routeros_vlans",
    "netbox_vlans": "netbox_vlans",
    "routeros_static_ips": "routeros_static_ipv4",
    "netbox_static_ips": "netbox_static_ipv4",
    "routeros_dynamic_ips": "routeros_dynamic_ipv4",
    "routeros_disabled_ips": "routeros_disabled_ipv4",
}
METRIC_PREFIX = "netbox_routeros_ipam_audit_"


def parse_audit(code: int, output: str) -> dict:
    """Fail closed on malformed or contradictory CLI output."""
    if code not in (0, 1):
        return {"status": 2}
    if not isinstance(output, str) or len(output) > 16384:
        return {"status": 2}
    fields = {}
    for line in output.splitlines():
        for marker in ("ROUTEROS IPAM AUDIT:", "Differences:", "Counts:"):
            if line.startswith(marker):
                if marker in fields:
                    return {"status": 2}
                fields[marker] = line[len(marker):].strip()
    status = fields.get("ROUTEROS IPAM AUDIT:")
    expected = "CLEAN" if code == 0 else "DRIFT"
    if status != expected:
        return {"status": 2}
    difference_text = fields.get("Differences:", "")
    if not re.fullmatch(r"(?:0|[1-9][0-9]{0,8})", difference_text):
        return {"status": 2}
    differences = int(difference_text)
    if (code == 0 and differences != 0) or (code == 1 and differences == 0):
        return {"status": 2}
    try:
        counts = json.loads(fields["Counts:"])
    except (KeyError, ValueError, TypeError):
        return {"status": 2}
    if (not isinstance(counts, dict) or set(counts) != set(COUNTS) or
            any(type(value) is not int or value < 0 or value > 1000000
                for value in counts.values())):
        return {"status": 2}
    return {"status": code, "differences": differences, "counts": counts}


def render_metrics(result: dict, timestamp: int) -> str:
    """Do not reuse stale differences or counts on ERROR."""
    lines = [
        "# HELP netbox_routeros_ipam_audit_status 0 clean, 1 drift, 2 error.",
        "# TYPE netbox_routeros_ipam_audit_status gauge",
        f"{METRIC_PREFIX}status {result['status']}",
        "# HELP netbox_routeros_ipam_audit_timestamp_seconds Unix time of last attempt.",
        "# TYPE netbox_routeros_ipam_audit_timestamp_seconds gauge",
        f"{METRIC_PREFIX}timestamp_seconds {timestamp}",
    ]
    if result["status"] in (0, 1):
        lines.extend([
            "# HELP netbox_routeros_ipam_audit_differences Number of verified differences.",
            "# TYPE netbox_routeros_ipam_audit_differences gauge",
            f"{METRIC_PREFIX}differences {result['differences']}",
        ])
        for source_name, suffix in COUNTS.items():
            name = METRIC_PREFIX + suffix
            lines += [
                f"# HELP {name} Validated inventory count.",
                f"# TYPE {name} gauge",
                f"{name} {result['counts'][source_name]}",
            ]
    return "\n".join(lines) + "\n"


def atomic_publish(directory: str, body: str) -> None:
    parent = Path(directory)
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or parent.is_symlink():
        raise OSError("Untrusted textfile output directory")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
                mode="w", encoding="ascii", prefix=".netbox-routeros-",
                suffix=".tmp", dir=str(parent), delete=False) as fh:
            temporary = Path(fh.name)
            fh.write(body)
            fh.flush()
            os.fsync(fh.fileno())
            os.fchmod(fh.fileno(), 0o640)
        os.replace(temporary, parent / FILE_NAME)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def execute_audit(*, timeout: int = 120) -> dict:
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "routeros.run_local_audit"],
            cwd=str(Path(__file__).resolve().parents[1]),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"status": 2}
    if len(completed.stdout) > 16384:
        return {"status": 2}
    try:
        stdout = completed.stdout.decode("utf-8")
    except UnicodeError:
        return {"status": 2}
    return parse_audit(completed.returncode, stdout)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        default="/var/lib/node_exporter/textfile_collector",
    )
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args(argv)
    if not 10 <= args.timeout <= 600:
        print("ROUTEROS IPAM METRICS: ERROR (invalid timeout)")
        return 2
    result = execute_audit(timeout=args.timeout)
    timestamp = int(datetime.now(timezone.utc).timestamp())
    try:
        atomic_publish(args.output_dir, render_metrics(result, timestamp))
    except OSError:
        print("ROUTEROS IPAM METRICS: ERROR (publishing failed)")
        return 2
    name = {0: "CLEAN", 1: "DRIFT", 2: "ERROR"}[result["status"]]
    print("ROUTEROS IPAM METRICS:", name)
    if "differences" in result:
        print("Differences:", result["differences"])
    return result["status"]


if __name__ == "__main__":
    sys.exit(main())
