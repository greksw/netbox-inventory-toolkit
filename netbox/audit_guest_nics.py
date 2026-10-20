#!/usr/bin/env python3
"""GET-only Proxmox / NetBox 4.7 guest vNIC drift audit.

Compares existing VMID mappings, guest resources, vNIC names, saved host bridge
descriptions and primary MACs. A known stopped base-image guest may explicitly
hold its duplicate MAC unassigned. Never writes to Proxmox or NetBox.

Exit: 0 clean, 1 drift, 2 source/config/API error. Private snapshots are 0600.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from collectors.proxmox_guests import collect, PveshGuestClient, GuestInventoryError
from collectors.proxmox_inventory import save_json
from netbox.drift_audit import NetBoxReadOnly, AuditError
from netbox.preview_guest_nics import (
    PreviewError, integer, validate_source, virtualization_listing,
    vm_interface_name,
)

MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
CLUSTER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,100}$")


class GuestDriftError(RuntimeError):
    pass


def netbox_primary_mac(record):
    """Fail closed when the serializer does not expose a trustworthy MAC."""
    if "primary_mac_address" in record:
        nested = record["primary_mac_address"]
        if nested is None:
            return None
        if isinstance(nested, dict):
            candidate = nested.get("mac_address")
        elif isinstance(nested, str):
            candidate = nested
        else:
            raise GuestDriftError("Unexpected primary MAC serializer data")
    elif "mac_address" in record:
        candidate = record["mac_address"]
        if candidate is None:
            return None
    else:
        raise GuestDriftError("NetBox interface MAC field unavailable")
    if not isinstance(candidate, str):
        raise GuestDriftError("Invalid NetBox MAC representation")
    mac = candidate.lower().replace("-", ":").strip()
    if not MAC_RE.fullmatch(mac):
        raise GuestDriftError("Invalid NetBox MAC value")
    return mac


def audit(source, vm_records, iface_records, *,
          cluster, expected_guests, held_vmids):
    guests = validate_source(source, expected_guests)
    if not isinstance(vm_records, list) or not isinstance(iface_records, list):
        raise GuestDriftError("Malformed NetBox virtualization inventory")
    if not CLUSTER_RE.fullmatch(cluster):
        raise GuestDriftError("Unsafe NetBox cluster name")
    if any(type(v) is not int or v <= 0 for v in held_vmids):
        raise GuestDriftError("Invalid held VMID list")
    if len(set(held_vmids)) != len(held_vmids):
        raise GuestDriftError("Duplicate held VMID")
    held_set = set(held_vmids)

    differences = []
    exceptions = []
    def difference(code, vmid=None, nic=None):
        rec = {"kind": code}
        if vmid is not None:
            rec["vmid"] = vmid
        if nic is not None:
            rec["interface"] = nic
        differences.append(rec)

    vms_by_id = {}
    vm_pks = {}
    for vm in vm_records:
        if not isinstance(vm, dict):
            raise GuestDriftError("Malformed NetBox VM")
        linked_cluster = vm.get("cluster")
        if not isinstance(linked_cluster, dict) or linked_cluster.get("name") != cluster:
            continue
        cf = vm.get("custom_fields")
        if not isinstance(cf, dict):
            raise GuestDriftError("Missing NetBox VM custom fields")
        vmid = integer(cf.get("proxmox_vmid"))
        pk = vm.get("id")
        if type(pk) is not int or vmid in vms_by_id or pk in vm_pks:
            raise GuestDriftError("Ambiguous NetBox guest identity")
        vms_by_id[vmid] = vm
        vm_pks[pk] = vmid

    for vmid in sorted(set(guests) - set(vms_by_id)):
        difference("netbox_vm_missing", vmid)
    for vmid in sorted(set(vms_by_id) - set(guests)):
        difference("netbox_vm_extra", vmid)

    netbox_ifaces = defaultdict(dict)
    for record in iface_records:
        if not isinstance(record, dict):
            raise GuestDriftError("Malformed NetBox interface")
        owner = record.get("virtual_machine")
        pk = owner.get("id") if isinstance(owner, dict) else None
        if pk not in vm_pks:
            continue
        vmid = vm_pks[pk]
        name = record.get("name")
        if not isinstance(name, str) or not name or name in netbox_ifaces[vmid]:
            raise GuestDriftError("Ambiguous NetBox interface identity")
        netbox_ifaces[vmid][name] = record

    # Inspect Proxmox MAC duplication independently; only explicitly approved
    # stopped guests may have an intentionally unassigned MAC in NetBox.
    source_macs = defaultdict(list)
    expected_names = defaultdict(set)
    for vmid, guest in sorted(guests.items()):
        vm = vms_by_id.get(vmid)
        if vm is not None:
            cf = vm["custom_fields"]
            for field, key in (
                ("proxmox_guest_type", "type"),
                ("proxmox_node", "node"),
                ("proxmox_power_state", "power_state"),
            ):
                if str(cf.get(field) or "").lower() != str(guest[key]).lower():
                    difference(field + "_mismatch", vmid)
            for netbox_field, source_field in (
                ("vcpus", guest.get("cpu", {}).get("configured_max_vcpus")),
                ("memory", guest.get("memory_mib")),
            ):
                try:
                    nval = integer(vm.get(netbox_field))
                    sval = integer(source_field)
                except (PreviewError, ValueError, TypeError):
                    difference(netbox_field + "_unavailable", vmid)
                else:
                    if nval != sval:
                        difference(netbox_field + "_mismatch", vmid)

        for nic in guest["interfaces"]:
            name = vm_interface_name(guest, nic)
            if name in expected_names[vmid]:
                raise GuestDriftError("Duplicate normalized Proxmox guest interface")
            expected_names[vmid].add(name)
            source_mac = nic["mac"].lower()
            source_macs[source_mac].append((vmid, name, guest["power_state"]))
            if vm is None:
                continue
            record = netbox_ifaces[vmid].get(name)
            if record is None:
                difference("vm_interface_missing", vmid, name)
                continue
            expected_desc = "Proxmox host bridge: " + nic["bridge"]
            if vmid in held_set:
                expected_desc += "; base-image MAC held"
            if record.get("description") != expected_desc:
                difference("host_bridge_description_mismatch", vmid, name)
            actual = netbox_primary_mac(record)
            if vmid in held_set:
                if actual is not None:
                    difference("held_mac_unexpectedly_assigned", vmid, name)
            elif actual is None:
                difference("vm_mac_missing", vmid, name)
            elif actual != source_mac:
                difference("vm_mac_mismatch", vmid, name)

    for vmid, available in netbox_ifaces.items():
        for name in sorted(set(available) - expected_names[vmid]):
            difference("vm_interface_extra", vmid, name)

    for mac, members in source_macs.items():
        held_in_group = [member for member in members if member[0] in held_set]
        if len(members) == 1:
            for member in held_in_group:
                difference("held_mac_no_longer_duplicated", member[0], member[1])
        elif len(members) == 2 and len(held_in_group) == 1:
            held = held_in_group[0]
            nonheld = next(member for member in members if member != held)
            if held[2] != "stopped" or nonheld[2] != "running":
                difference("duplicate_mac_state_changed", held[0], held[1])
            else:
                exceptions.append({
                    "type": "approved_duplicate_mac",
                    "held_vmid": held[0],
                    "assigned_vmid": nonheld[0],
                })
        else:
            for vmid, name, _ in members:
                difference("unapproved_duplicate_source_mac", vmid, name)

    for vmid in sorted(held_set - set(guests)):
        difference("held_vm_not_in_source", vmid)

    expected_ifaces = sum(len(g["interfaces"]) for g in guests.values())
    count_ifaces = sum(len(items) for items in netbox_ifaces.values())
    mac_checked = sum(
        1 for vmid, names in netbox_ifaces.items()
        for name, record in names.items()
        if name in expected_names[vmid] and vmid not in held_set
        and netbox_primary_mac(record) is not None
    )
    result = {
        "schema_version": "guest-nic-drift-0.1",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "status": "drift" if differences else "clean",
        "counts": {
            "proxmox_guests": len(guests),
            "netbox_guests": len(vms_by_id),
            "proxmox_interfaces": expected_ifaces,
            "netbox_interfaces": count_ifaces,
            "macs_present": mac_checked,
            "macs_held_by_policy": len(held_set),
            "approved_exceptions": len(exceptions),
            "differences": len(differences),
        },
        "by_kind": dict(sorted(Counter(item["kind"] for item in differences).items())),
        "differences": differences,
        "exceptions": exceptions,
        "netbox_writes": 0,
        "api_methods": ["GET"],
    }
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only Proxmox guest vNIC drift audit")
    parser.add_argument("--cluster", required=True)
    parser.add_argument("--expected-guests", type=int, required=True)
    parser.add_argument("--held-vmid", type=int, action="append", default=[])
    parser.add_argument("--inventory", type=Path, help="Existing fresh private Proxmox guest snapshot")
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.expected_guests <= 0 or not CLUSTER_RE.fullmatch(args.cluster):
        parser.error("Invalid guest count or cluster")
    try:
        args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if args.inventory:
            with args.inventory.open(encoding="utf-8") as handle:
                source = json.load(handle)
        else:
            source = collect(PveshGuestClient(), expected_guests=args.expected_guests)
            save_json(source, args.output_dir / "guest-source-latest.json")
        client = NetBoxReadOnly(
            os.environ.get("NETBOX_URL", ""),
            os.environ.get("NETBOX_TOKEN", ""),
            os.environ.get("NETBOX_CA_FILE") or None,
        )
        vms = virtualization_listing(client, "/api/virtualization/virtual-machines/")
        nics = virtualization_listing(client, "/api/virtualization/interfaces/")
        report = audit(source, vms, nics, cluster=args.cluster,
                       expected_guests=args.expected_guests,
                       held_vmids=args.held_vmid)
        save_json(report, args.output_dir / "guest-drift-latest.json")
        print("GUEST DRIFT:", report["status"].upper())
        print("COUNTS:", report["counts"])
        print("CATEGORIES:", report["by_kind"])
        return 1 if report["status"] == "drift" else 0
    except (GuestInventoryError, GuestDriftError, PreviewError, AuditError,
            OSError, ValueError, TypeError, KeyError) as exc:
        print("GUEST DRIFT: ERROR; reason:", type(exc).__name__, file=sys.stderr)
        try:
            save_json({
                "status": "error",
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "error_type": type(exc).__name__,
                "netbox_writes": 0,
            }, args.output_dir / "guest-drift-latest.json")
        except OSError:
            pass
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
