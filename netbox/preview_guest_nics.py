#!/usr/bin/env python3
"""Read-only preview for importing Proxmox guest NICs into NetBox.

Only pvesh GET and HTTPS GET are used. No NetBox writes.
Proxmox host bridge names are metadata, not VMInterface.bridge references.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import json
import os
from pathlib import Path
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlsplit
from urllib.request import Request

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from netbox.drift_audit import NetBoxReadOnly, AuditError
from collectors.proxmox_inventory import PveshClient, save_json

MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
NIC_RE = re.compile(r"^net[0-9]+$")
CLUSTER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,100}$")


class PreviewError(RuntimeError):
    pass


def virtualization_listing(client, endpoint):
    """GET-only, origin-restricted pagination on virtualization endpoints."""
    if endpoint not in ("/api/virtualization/virtual-machines/",
                        "/api/virtualization/interfaces/"):
        raise PreviewError("Unexpected NetBox virtualization endpoint")
    current = client.origin + endpoint + "?" + urlencode({"limit": 200})
    seen, results = set(), []
    for _ in range(100):
        parsed = urlsplit(current)
        if (parsed.scheme != "https" or
                "https://" + parsed.netloc != client.origin or
                parsed.path != endpoint or current in seen):
            raise PreviewError("Unsafe NetBox pagination")
        seen.add(current)
        request = Request(current, method="GET", headers={
            "Authorization": client.authorization,
            "Accept": "application/json",
        })
        try:
            with client.opener.open(request, timeout=15) as response:
                body = json.load(response)
        except (OSError, HTTPError, URLError, ValueError) as exc:
            raise PreviewError("NetBox read-only HTTPS request failed") from exc
        if not isinstance(body, dict) or not isinstance(body.get("results"), list):
            raise PreviewError("Malformed NetBox virtualization response")
        results.extend(body["results"])
        link = body.get("next")
        if link is None:
            if body.get("count") is not None and body["count"] != len(results):
                raise PreviewError("Incomplete NetBox pagination")
            return results
        if not isinstance(link, str):
            raise PreviewError("Malformed NetBox pagination link")
        current = urljoin(client.origin + "/", link)
    raise PreviewError("NetBox pagination limit reached")


def integer(value):
    if value is None or isinstance(value, bool):
        raise PreviewError("Missing or invalid numeric field")
    try:
        number = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        raise PreviewError("Invalid numeric field") from None
    if not number.is_finite() or number != number.to_integral_value():
        raise PreviewError("Nonintegral numeric field")
    return int(number)


def validate_source(source, expected):
    if not isinstance(source, dict) or source.get("schema_version") != "guests-0.1":
        raise PreviewError("Unsupported Proxmox guest snapshot")
    guests, summary = source.get("guests"), source.get("summary")
    if (not isinstance(guests, list) or not isinstance(summary, dict) or
            len(guests) != expected or summary.get("collected") != expected or
            summary.get("selected") != expected or summary.get("errors") != 0):
        raise PreviewError("Incomplete Proxmox guest snapshot")
    try:
        stamp = datetime.fromisoformat(source.get("collected_at"))
        age = (datetime.now(timezone.utc) - stamp).total_seconds()
    except (TypeError, ValueError):
        raise PreviewError("Missing snapshot timestamp") from None
    if stamp.tzinfo is None or age < -300 or age > 86400:
        raise PreviewError("Guest snapshot is outside 24-hour freshness window")
    by_id = {}
    for guest in guests:
        if not isinstance(guest, dict):
            raise PreviewError("Malformed guest in snapshot")
        vmid = integer(guest.get("vmid"))
        if (vmid < 1 or vmid in by_id or guest.get("type") not in ("qemu", "lxc") or
                guest.get("power_state") not in ("running", "stopped") or
                not isinstance(guest.get("node"), str)):
            raise PreviewError("Invalid or duplicate Proxmox guest")
        nics = guest.get("interfaces")
        if not isinstance(nics, list):
            raise PreviewError("Incomplete Proxmox vNIC collection")
        keys = set()
        for nic in nics:
            if (not isinstance(nic, dict) or not isinstance(nic.get("key"), str) or
                    not NIC_RE.fullmatch(nic["key"])):
                raise PreviewError("Malformed vNIC entry")
            if nic["key"] in keys:
                raise PreviewError("Duplicate guest vNIC key")
            keys.add(nic["key"])
            mac = nic.get("mac")
            if not isinstance(mac, str) or not MAC_RE.fullmatch(mac.lower()):
                raise PreviewError("Missing/invalid vNIC MAC")
            if not isinstance(nic.get("bridge"), str) or not nic["bridge"]:
                raise PreviewError("Missing Proxmox Linux bridge")
        by_id[vmid] = guest
    return by_id


def netbox_by_vmid(vms, cluster, expected):
    by_id = {}
    for vm in vms:
        if not isinstance(vm, dict):
            raise PreviewError("Malformed NetBox VM response")
        info = vm.get("cluster")
        if not isinstance(info, dict) or info.get("name") != cluster:
            continue
        cf = vm.get("custom_fields")
        if not isinstance(cf, dict):
            raise PreviewError("Missing NetBox custom fields")
        vmid = integer(cf.get("proxmox_vmid"))
        if vmid in by_id or not isinstance(vm.get("id"), int):
            raise PreviewError("Duplicate VMID or invalid NetBox VM ID")
        by_id[vmid] = vm
    if len(by_id) != expected:
        raise PreviewError("Unexpected number of NetBox VMs in cluster")
    return by_id


def vm_interface_name(guest, nic):
    # QEMU: stable Proxmox config key net0/net1. LXC: guest NIC name eth0.
    if guest["type"] == "lxc" and isinstance(nic.get("name"), str) and nic["name"]:
        name = nic["name"]
    else:
        name = nic["key"]
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", name):
        raise PreviewError("Unsafe or malformed VMInterface name")
    return name


def preview(source, vm_records, iface_records, bridge_client, cluster, expected):
    guests = validate_source(source, expected)
    netbox_vms = netbox_by_vmid(vm_records, cluster, expected)
    if set(guests) != set(netbox_vms):
        raise PreviewError("Proxmox and NetBox VMID sets differ")
    by_vm_id = {vm["id"]: vmid for vmid, vm in netbox_vms.items()}
    existing = defaultdict(dict)
    for record in iface_records:
        if not isinstance(record, dict):
            raise PreviewError("Malformed NetBox VMInterface response")
        owner = record.get("virtual_machine")
        owner_id = owner.get("id") if isinstance(owner, dict) else None
        if owner_id not in by_vm_id:
            continue
        name = record.get("name")
        if not isinstance(name, str) or name in existing[owner_id]:
            raise PreviewError("Duplicate/malformed existing NetBox VMInterface")
        existing[owner_id][name] = record

    bridges = {}
    for node in sorted({g["node"] for g in guests.values()}):
        records = bridge_client.get(f"/nodes/{node}/network")
        if not isinstance(records, list):
            raise PreviewError("Incomplete Proxmox bridge list")
        bridges[node] = {
            entry["iface"] for entry in records if isinstance(entry, dict) and
            entry.get("type") in ("bridge", "OVSBridge") and
            isinstance(entry.get("iface"), str)
        }

    warnings, plan, source_macs = [], [], defaultdict(list)
    expected_names = defaultdict(set)
    for vmid, guest in sorted(guests.items()):
        vm = netbox_vms[vmid]
        cf = vm["custom_fields"]
        if (str(cf.get("proxmox_guest_type")).lower() != guest["type"] or
                str(cf.get("proxmox_node")).lower() != guest["node"].lower() or
                str(cf.get("proxmox_power_state")).lower() != guest["power_state"] or
                integer(vm.get("vcpus")) != integer(guest["cpu"]["configured_max_vcpus"]) or
                integer(vm.get("memory")) != integer(guest["memory_mib"])):
            raise PreviewError("Identity, placement, CPU or RAM drift; refresh first")
        for nic in guest["interfaces"]:
            name = vm_interface_name(guest, nic)
            if name in expected_names[vmid]:
                raise PreviewError("Duplicate normalized interface name")
            expected_names[vmid].add(name)
            item = {
                "vmid": vmid,
                "vm_interface_name": name,
                "proxmox_config_key": nic["key"],
                "proxmox_bridge": nic["bridge"],
                "mac": nic["mac"].lower(),
                "power_state": guest["power_state"],
                "netbox_vm_id": vm["id"],
                "action": ("already_present" if name in existing[vm["id"]]
                           else "create_vm_interface"),
                "mac_action": None,
            }
            if nic["bridge"] not in bridges[guest["node"]]:
                warnings.append({"type": "bridge_not_found", "vmid": vmid,
                                 "interface": name, "bridge": nic["bridge"]})
            plan.append(item)
            source_macs[item["mac"]].append(item)
    for vmid, vm in netbox_vms.items():
        for name in sorted(set(existing[vm["id"]]) - expected_names[vmid]):
            warnings.append({"type": "extra_netbox_vm_interface", "vmid": vmid,
                             "interface": name})

    for mac, records in source_macs.items():
        if len(records) == 1:
            records[0]["mac_action"] = "eligible_after_review"
            continue
        active = [r for r in records if r["power_state"] == "running"]
        if len(active) == 1:
            active[0]["mac_action"] = "eligible_after_review"
        for record in records:
            if record["mac_action"] is None:
                record["mac_action"] = "hold_duplicate_mac"
        warnings.append({"type": "duplicate_mac",
                         "vmids": sorted(r["vmid"] for r in records),
                         "mac_masked": "**:**:**:" + mac[-8:]})

    return {
        "schema_version": "vm-nic-preview-0.1",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "cluster": cluster,
        "read_only": True,
        "netbox_writes": 0,
        "summary": {
            "vm_count": len(guests),
            "vnic_count": len(plan),
            "create_vm_interface": sum(p["action"] == "create_vm_interface" for p in plan),
            "already_present": sum(p["action"] == "already_present" for p in plan),
            "mac_eligible_after_review": sum(p["mac_action"] == "eligible_after_review" for p in plan),
            "mac_held": sum(p["mac_action"] == "hold_duplicate_mac" for p in plan),
            "warnings": dict(sorted(Counter(w["type"] for w in warnings).items())),
        },
        "warnings": warnings,
        "plan": plan,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="GET-only Proxmox VMInterface preview")
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--cluster", required=True)
    parser.add_argument("--expected-guests", type=int, required=True)
    parser.add_argument("--output", type=Path, default=Path("output/guest-nics-preview.json"))
    args = parser.parse_args(argv)
    if args.expected_guests < 1 or not CLUSTER_RE.fullmatch(args.cluster):
        parser.error("Invalid cluster name or expected count")
    try:
        with args.inventory.open(encoding="utf-8") as file:
            source = json.load(file)
        client = NetBoxReadOnly(
            os.environ.get("NETBOX_URL", ""),
            os.environ.get("NETBOX_TOKEN", ""),
            os.environ.get("NETBOX_CA_FILE") or None,
        )
        vms = virtualization_listing(client, "/api/virtualization/virtual-machines/")
        nics = virtualization_listing(client, "/api/virtualization/interfaces/")
        report = preview(source, vms, nics, PveshClient(), args.cluster,
                         args.expected_guests)
        save_json(report, args.output)
    except (PreviewError, AuditError, OSError, ValueError, KeyError, TypeError) as exc:
        print("PREVIEW: ERROR; type:", type(exc).__name__, file=sys.stderr)
        return 2
    print("PREVIEW: READ-ONLY")
    print("COUNTS:", report["summary"])
    print("WARNINGS:", report["warnings"])
    print("PRIVATE REPORT:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
