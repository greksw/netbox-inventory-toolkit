#!/usr/bin/env python3
"""Offline, read-only RouterOS 7 <-> NetBox IPAM snapshot comparison.

No SSH, network requests, RouterOS API calls, NetBox writes or remediation.
Inputs are private reviewed JSON exports. Outputs hide private identifiers.
Exit: 0 CLEAN, 1 DRIFT, 2 ERROR (missing, malformed or stale evidence).
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import sys

SOURCE_SCHEMA = "routeros-ipam-0.1"
NETBOX_SCHEMA = "netbox-router-ipam-0.1"
NAME_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")


class IPAMAuditError(ValueError):
    pass


def checked_time(value: object, *, max_age_minutes: int, now=None) -> None:
    if not isinstance(value, str):
        raise IPAMAuditError("Missing snapshot timestamp")
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            raise ValueError()
    except ValueError:
        raise IPAMAuditError("Invalid snapshot timestamp") from None
    diff = ((now or datetime.now(timezone.utc)) - stamp).total_seconds()
    if diff < -300 or diff > max_age_minutes * 60:
        raise IPAMAuditError("Snapshot out of accepted age range")


def checked_name(value: object) -> str:
    if not isinstance(value, str) or not NAME_RE.fullmatch(value):
        raise IPAMAuditError("Invalid interface name")
    return value


def checked_address(value: object) -> str:
    if not isinstance(value, str):
        raise IPAMAuditError("Missing IPv4 CIDR")
    try:
        iface = ipaddress.ip_interface(value)
        if not isinstance(iface, ipaddress.IPv4Interface):
            raise ValueError()
    except ValueError:
        raise IPAMAuditError("Invalid IPv4 CIDR") from None
    if str(iface) != value:
        raise IPAMAuditError("Noncanonical IPv4 CIDR")
    return str(iface)


def checked_prefix(value: object) -> str:
    if not isinstance(value, str):
        raise IPAMAuditError("Missing prefix")
    try:
        network = ipaddress.ip_network(value, strict=True)
        if not isinstance(network, ipaddress.IPv4Network):
            raise ValueError()
    except ValueError:
        raise IPAMAuditError("Invalid IPv4 prefix") from None
    if str(network) != value:
        raise IPAMAuditError("Noncanonical IPv4 prefix")
    return str(network)


def checked_vid(value: object) -> int:
    if type(value) is not int or not 1 <= value <= 4094:
        raise IPAMAuditError("Invalid VLAN ID")
    return value


def unique_pairs(rows: list, allowed_fields: set[str], name: str) -> None:
    if not isinstance(rows, list):
        raise IPAMAuditError("Missing " + name)
    for row in rows:
        if not isinstance(row, dict) or set(row) != allowed_fields:
            raise IPAMAuditError("Unexpected fields in " + name)


def normalize_router(raw: dict, *, max_age_minutes: int):
    if not isinstance(raw, dict) or raw.get("schema_version") != SOURCE_SCHEMA:
        raise IPAMAuditError("Unsupported RouterOS snapshot schema")
    checked_time(raw.get("collected_at"), max_age_minutes=max_age_minutes)
    vlans = raw.get("vlans")
    ips = raw.get("addresses")
    unique_pairs(vlans, {"vid", "name", "parent", "disabled"}, "VLANs")
    unique_pairs(ips, {"address", "interface", "dynamic", "disabled"}, "addresses")
    vid_index, vlan_names = {}, set()
    for row in vlans:
        vid = checked_vid(row["vid"])
        name = checked_name(row["name"])
        checked_name(row["parent"])
        if type(row["disabled"]) is not bool:
            raise IPAMAuditError("Invalid VLAN disabled flag")
        if vid in vid_index or name in vlan_names:
            raise IPAMAuditError("Duplicate source VLAN")
        vid_index[vid] = row
        vlan_names.add(name)
    static, dynamic, disabled = set(), set(), set()
    for row in ips:
        cidr = checked_address(row["address"])
        iface = checked_name(row["interface"])
        if type(row["dynamic"]) is not bool or type(row["disabled"]) is not bool:
            raise IPAMAuditError("Invalid address state flag")
        key = (cidr, iface)
        if key in static or key in dynamic or key in disabled:
            raise IPAMAuditError("Duplicate RouterOS IPv4 assignment")
        if row["disabled"]:
            disabled.add(key)
        elif row["dynamic"]:
            dynamic.add(key)
        else:
            static.add(key)
    return vid_index, static, dynamic, disabled


def normalize_netbox(raw: dict, *, max_age_minutes: int):
    if not isinstance(raw, dict) or raw.get("schema_version") != NETBOX_SCHEMA:
        raise IPAMAuditError("Unsupported NetBox snapshot schema")
    checked_time(raw.get("collected_at"), max_age_minutes=max_age_minutes)
    vlans, ips = raw.get("vlans"), raw.get("addresses")
    unique_pairs(vlans, {"vid", "prefix"}, "NetBox VLANs")
    unique_pairs(ips, {"address", "interface"}, "NetBox addresses")
    vid_prefix = {}
    for row in vlans:
        vid = checked_vid(row["vid"])
        prefix = checked_prefix(row["prefix"])
        if vid in vid_prefix:
            raise IPAMAuditError("Duplicate NetBox VLAN")
        vid_prefix[vid] = prefix
    addresses = set()
    for row in ips:
        pair = (checked_address(row["address"]), checked_name(row["interface"]))
        if pair in addresses:
            raise IPAMAuditError("Duplicate NetBox address assignment")
        addresses.add(pair)
    return vid_prefix, addresses


def compare(router: dict, netbox: dict, *, expected_vlans: int,
            expected_static_addresses: int, max_age_minutes: int = 60,
            approved_dynamic: tuple[tuple[str, str], ...] = ()) -> dict:
    """Compare exact static interface/CIDR pairs and VLAN ID-to-prefix mapping.

    This is intentionally narrower than full RouterOS inventory synchronization.
    No confidential object identity is included in the returned report.
    """
    if (type(expected_vlans) is not int or expected_vlans < 1 or
            type(expected_static_addresses) is not int or
            expected_static_addresses < 1 or
            type(max_age_minutes) is not int or max_age_minutes < 1):
        raise IPAMAuditError("Invalid expected counts or maximum snapshot age")
    rv, static, dynamic, disabled = normalize_router(
        router, max_age_minutes=max_age_minutes)
    nv, ni = normalize_netbox(netbox, max_age_minutes=max_age_minutes)
    if len(rv) != expected_vlans or len(static) != expected_static_addresses:
        raise IPAMAuditError("RouterOS collection does not match approved counts")
    if len(nv) != expected_vlans or len(ni) != expected_static_addresses:
        raise IPAMAuditError("NetBox inventory does not match approved counts")
    if any(v["disabled"] for v in rv.values()):
        raise IPAMAuditError("Disabled VLAN present; review the baseline first")
    categories = Counter()
    categories["vlan_missing_netbox"] += len(set(rv) - set(nv))
    categories["vlan_extra_netbox"] += len(set(nv) - set(rv))
    for vid in set(rv) & set(nv):
        gateway_networks = {
            str(ipaddress.ip_interface(addr).network)
            for addr, iface in static if iface == rv[vid]["name"]
        }
        if len(gateway_networks) != 1 or nv[vid] not in gateway_networks:
            categories["vlan_prefix_mismatch"] += 1
    categories["static_ip_missing_netbox"] += len(static - ni)
    categories["static_ip_extra_netbox"] += len(ni - static)
    approved = set()
    for row in approved_dynamic:
        if not isinstance(row, (tuple, list)) or len(row) != 2:
            raise IPAMAuditError("Invalid approved dynamic address record")
        pair = (checked_address(row[0]), checked_name(row[1]))
        if pair in approved:
            raise IPAMAuditError("Duplicate approved dynamic address")
        approved.add(pair)
    categories["dynamic_review_required"] += len(dynamic - approved)
    categories["approved_dynamic_missing"] += len(approved - dynamic)
    categories["disabled_address_review_required"] += len(disabled)
    # Active dynamic entries must never accidentally be counted as static NetBox records.
    categories["dynamic_also_in_netbox"] += len(dynamic & ni)
    differences = sum(categories.values())
    return {
        "status": "DRIFT" if differences else "CLEAN",
        "differences": differences,
        "categories": dict(sorted((k, v) for k, v in categories.items() if v)),
        "counts": {
            "routeros_vlans": len(rv),
            "netbox_vlans": len(nv),
            "routeros_static_ips": len(static),
            "netbox_static_ips": len(ni),
            "routeros_dynamic_ips": len(dynamic),
            "routeros_disabled_ips": len(disabled),
        },
    }


def read_private_json(path: str) -> dict:
    p = Path(path)
    if not p.is_file() or p.is_symlink() or p.stat().st_size > 2_000_000:
        raise IPAMAuditError("Missing, unsafe or oversized snapshot file")
    if p.stat().st_mode & 0o077:
        raise IPAMAuditError("Snapshot must not be group/world accessible")
    try:
        with p.open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, ValueError):
        raise IPAMAuditError("Could not read JSON snapshot") from None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--router-snapshot", required=True)
    parser.add_argument("--netbox-snapshot", required=True)
    parser.add_argument("--expected-vlans", type=int, required=True)
    parser.add_argument("--expected-static-addresses", type=int, required=True)
    parser.add_argument("--max-age-minutes", type=int, default=60)
    args = parser.parse_args(argv)
    try:
        result = compare(
            read_private_json(args.router_snapshot),
            read_private_json(args.netbox_snapshot),
            expected_vlans=args.expected_vlans,
            expected_static_addresses=args.expected_static_addresses,
            max_age_minutes=args.max_age_minutes,
        )
    except IPAMAuditError:
        print("ROUTEROS IPAM AUDIT: ERROR")
        print("REASON: incomplete, stale, invalid or inaccessible snapshot")
        return 2
    print("ROUTEROS IPAM AUDIT:", result["status"])
    print("COUNTS:", result["counts"])
    print("CATEGORIES:", result["categories"])
    return 0 if result["status"] == "CLEAN" else 1


if __name__ == "__main__":
    sys.exit(main())
