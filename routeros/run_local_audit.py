#!/usr/bin/env python3
"""One-shot, read-only RouterOS SSH and NetBox HTTPS IPAM reconciliation.

Local, root-only JSON configuration is mandatory. Nothing is saved or changed
on RouterOS or NetBox. Output includes aggregate counts and categories only.
Exit codes: 0=CLEAN, 1=DRIFT, 2=ERROR (including incomplete evidence).
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys

from routeros.ipam_audit import IPAMAuditError, checked_address, checked_name, compare
from routeros.ipam_sources import NetBoxReader, netbox_snapshot, routeros_snapshot
from routeros.ssh_source import RouterOSSSHReader

DEFAULT_CONFIG = "/etc/netbox-inventory/routeros-ipam.json"


def read_root_private(path: str, *, size_limit: int) -> str:
    """Prevent accidental reads of shared/symlinked config and token files."""
    if not isinstance(path, str) or not os.path.isabs(path):
        raise IPAMAuditError("A private absolute file path is required")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError:
        raise IPAMAuditError("Private file unavailable") from None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or (info.st_mode & 0o077)
                or not 0 < info.st_size <= size_limit):
            raise IPAMAuditError("Unsafe private file permissions or size")
        with os.fdopen(os.dup(fd), "rb") as source:
            raw = source.read(size_limit + 1)
        if not 0 < len(raw) <= size_limit:
            raise IPAMAuditError("Invalid private file size")
        return raw.decode("utf-8")
    except (OSError, UnicodeError):
        raise IPAMAuditError("Private file unreadable") from None
    finally:
        os.close(fd)


def require_fields(obj: object, required: set[str], label: str) -> dict:
    if not isinstance(obj, dict) or set(obj) != required:
        raise IPAMAuditError("Invalid " + label + " configuration")
    return obj


def validate_config(raw: object) -> dict:
    cfg = require_fields(raw, {
        "schema_version", "routeros", "netbox", "baseline",
        "approved_dynamic", "max_age_minutes",
    }, "audit")
    if cfg["schema_version"] != "routeros-netbox-ipam-live-v1":
        raise IPAMAuditError("Unsupported audit config version")
    router = require_fields(cfg["routeros"], {
        "host", "username", "identity_file", "known_hosts_file",
    }, "RouterOS")
    netbox = require_fields(cfg["netbox"], {
        "origin", "token_file", "ca_file", "router_name",
        "site_slug", "vlan_group_slug",
    }, "NetBox")
    baseline = require_fields(cfg["baseline"], {
        "vlans", "static_ipv4",
    }, "baseline")
    for name in ("vlans", "static_ipv4"):
        if type(baseline[name]) is not int or not 1 <= baseline[name] <= 100000:
            raise IPAMAuditError("Invalid baseline counts")
    if (type(cfg["max_age_minutes"]) is not int or
            not 1 <= cfg["max_age_minutes"] <= 1440):
        raise IPAMAuditError("Invalid maximum snapshot age")
    if not isinstance(cfg["approved_dynamic"], list) or len(cfg["approved_dynamic"]) > 100:
        raise IPAMAuditError("Invalid reviewed dynamic list")
    for field in ("host", "username", "identity_file", "known_hosts_file"):
        if not isinstance(router[field], str) or not router[field]:
            raise IPAMAuditError("Missing RouterOS setting")
    for field in ("origin", "token_file", "ca_file", "router_name", "site_slug", "vlan_group_slug"):
        if not isinstance(netbox[field], str) or not netbox[field]:
            raise IPAMAuditError("Missing NetBox setting")
    reviewed = set()
    for entry in cfg["approved_dynamic"]:
        require_fields(entry, {"address", "interface"}, "approved dynamic")
        pair = (checked_address(entry["address"]), checked_name(entry["interface"]))
        if pair in reviewed:
            raise IPAMAuditError("Duplicate reviewed dynamic address")
        reviewed.add(pair)
    return cfg


def run_once(cfg: dict) -> dict:
    cfg = validate_config(cfg)
    router = cfg["routeros"]
    nb = cfg["netbox"]
    token = read_root_private(nb["token_file"], size_limit=512).strip()
    if not token:
        raise IPAMAuditError("Missing NetBox token")

    ros = routeros_snapshot(RouterOSSSHReader(
        host=router["host"],
        username=router["username"],
        identity_file=router["identity_file"],
        known_hosts_file=router["known_hosts_file"],
    ))
    netbox = netbox_snapshot(
        NetBoxReader(origin=nb["origin"], token=token, ca_file=nb["ca_file"]),
        router_name=nb["router_name"],
        site_slug=nb["site_slug"],
        vlan_group_slug=nb["vlan_group_slug"],
    )
    return compare(
        ros, netbox,
        expected_vlans=cfg["baseline"]["vlans"],
        expected_static_addresses=cfg["baseline"]["static_ipv4"],
        max_age_minutes=cfg["max_age_minutes"],
        approved_dynamic=tuple(
            (entry["address"], entry["interface"])
            for entry in cfg["approved_dynamic"]
        ),
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=DEFAULT_CONFIG,
                        help="Root-owned mode 0600 local JSON configuration")
    args = parser.parse_args(argv)
    try:
        cfg = json.loads(read_root_private(args.config, size_limit=16384))
        result = run_once(cfg)
        if result["status"] not in ("CLEAN", "DRIFT"):
            raise IPAMAuditError("Unexpected result status")
        print("ROUTEROS IPAM AUDIT:", result["status"])
        print("Differences:", result["differences"])
        print("Categories:", json.dumps(result["categories"], sort_keys=True))
        print("Counts:", json.dumps(result["counts"], sort_keys=True))
        return 0 if result["status"] == "CLEAN" else 1
    except Exception:
        # Do not leak tokens, hostnames, IP addresses or server response bodies.
        print("ROUTEROS IPAM AUDIT: ERROR")
        return 2


if __name__ == "__main__":
    sys.exit(main())
