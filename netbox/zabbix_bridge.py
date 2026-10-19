#!/usr/bin/env python3
"""Minimal and sanitized status bridge: root-owned private audit -> Zabbix.

export: called by systemd ExecStopPost as root, with SERVICE_RESULT passed by
systemd. read: called by the unprivileged Zabbix agent.

Never exposes inventory, IP addresses, MACs, serials or API credentials.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import grp
import json
import os
from pathlib import Path
import tempfile
import time

SOURCE = Path("/var/lib/netbox-inventory/drift-latest.json")
PUBLIC = Path("/var/lib/netbox-inventory-zabbix/metrics.json")
KEYS = ("status", "differences", "timestamp")
MAX_REPORT_AGE = 1200  # A result older than 20 min cannot belong to this run.


def summarize(report: object, service_result: str, now: int | None = None) -> dict[str, int]:
    """0=clean, 1=drift, 2=audit/error; timestamp=last completed attempt."""
    timestamp = int(time.time() if now is None else now)
    metric = {"status": 2, "differences": 0, "timestamp": timestamp}
    if service_result != "success" or not isinstance(report, dict):
        return metric
    state = report.get("status")
    if state not in ("clean", "drift"):
        return metric
    try:
        checked_at = datetime.fromisoformat(report["checked_at"])
        if checked_at.tzinfo is None:
            return metric
        checked_at = int(checked_at.astimezone(timezone.utc).timestamp())
        if not -300 <= timestamp - checked_at <= MAX_REPORT_AGE:
            return metric
        diff = report["counts"]["differences"]
        if isinstance(diff, bool) or not isinstance(diff, int) or diff < 0:
            return metric
        if (state == "clean" and diff != 0) or (state == "drift" and diff == 0):
            return metric
    except (KeyError, ValueError, TypeError, OverflowError, AttributeError):
        return metric
    metric["status"] = 0 if state == "clean" else 1
    metric["differences"] = diff
    return metric


def read_report(path: Path) -> object:
    try:
        with path.open(encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def write_private_group_file(path: Path, report: dict[str, int]) -> None:
    """Atomic root:zabbix 0640 output; directory must preexist and be private."""
    if not path.parent.is_dir():
        raise OSError("Metric directory not installed")
    gid = grp.getgrnam("zabbix").gr_gid
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent,
            prefix=".metrics-", delete=False
        ) as fh:
            temporary = Path(fh.name)
            os.fchmod(fh.fileno(), 0o640)
            os.fchown(fh.fileno(), 0, gid)
            json.dump(report, fh, separators=(",", ":"), sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def read_metric(path: Path, key: str) -> int:
    """Fail closed: unreadable/corrupt status => error; timestamp => stale."""
    defaults = {"status": 2, "differences": 0, "timestamp": 0}
    try:
        if path.stat().st_size > 4096:
            return defaults[key]
        with path.open(encoding="utf-8") as fh:
            payload = json.load(fh)
        if not isinstance(payload, dict):
            return defaults[key]
        values = [payload.get(k) for k in KEYS]
        if any(type(value) is not int for value in values):
            return defaults[key]
        if (payload["status"] not in (0, 1, 2) or
                payload["differences"] < 0 or payload["timestamp"] <= 0):
            return defaults[key]
        return payload[key]
    except (OSError, ValueError):
        return defaults[key]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("export")
    read = subparsers.add_parser("read")
    read.add_argument("key", choices=KEYS)
    args = parser.parse_args(argv)
    if args.command == "read":
        print(read_metric(PUBLIC, args.key))
        return 0
    report = read_report(SOURCE)
    metric = summarize(report, os.environ.get("SERVICE_RESULT", "error"))
    try:
        write_private_group_file(PUBLIC, metric)
    except (OSError, KeyError) as exc:
        # Never log report, environment or raw error messages.
        print("ZABBIX_BRIDGE: unable to write safe metrics: " +
              type(exc).__name__, flush=True)
        return 1
    print("ZABBIX_BRIDGE:", metric, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
