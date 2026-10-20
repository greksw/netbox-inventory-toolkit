#!/usr/bin/env python3
"""Guarded NetBox 4.7 VMInterface import from a reviewed GET-only preview.

Invoke run() from manage.py shell on NetBox. Dry-run is the default. Apply
requires explicit confirmation and is all-or-nothing in a PostgreSQL transaction.
Only VMInterface and associated primary MACAddress objects may be created.
No Proxmox changes and no updates to VM resources, VLAN, VRF or IPAM.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path
import re

VALID_MAC = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
VALID_NAME = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
VALID_BRIDGE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
CONFIRM = "APPLY_REVIEWED_GUEST_INTERFACES"


class GuestNICImportError(RuntimeError):
    """Abort instead of partially importing or guessing topology."""


def _integer(value):
    if type(value) is not int:
        raise GuestNICImportError("Invalid integer in preview")
    return value


def verify_preview(report, *, cluster, expected_vms, expected_nics,
                   expected_macs, expected_held, freshness_seconds=3600):
    """Validate the planned changes independently of NetBox/Django."""
    if (not isinstance(report, dict) or report.get("schema_version") != "vm-nic-preview-0.1"
            or report.get("read_only") is not True or report.get("netbox_writes") != 0
            or report.get("cluster") != cluster):
        raise GuestNICImportError("Wrong preview schema, scope or write state")
    if (not isinstance(cluster, str) or
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,100}", cluster)):
        raise GuestNICImportError("Invalid NetBox cluster name")
    if any(type(value) is not int or value < 0
           for value in (expected_vms, expected_nics, expected_macs)):
        raise GuestNICImportError("Invalid expected counts")
    if expected_vms < 1 or expected_nics < 1 or expected_macs < 1:
        raise GuestNICImportError("Expected counts must be positive")
    if (not isinstance(expected_held, (tuple, list, set)) or
            any(type(vmid) is not int or vmid <= 0 for vmid in expected_held)):
        raise GuestNICImportError("Invalid held VMIDs")
    held = set(expected_held)

    try:
        created = datetime.fromisoformat(report["checked_at"])
        delta = (datetime.now(timezone.utc) - created).total_seconds()
    except (KeyError, TypeError, ValueError):
        raise GuestNICImportError("Missing preview timestamp") from None
    if created.tzinfo is None or delta < -300 or delta > freshness_seconds:
        raise GuestNICImportError("Preview expired; regenerate on Proxmox")

    plan, summary = report.get("plan"), report.get("summary")
    if not isinstance(plan, list) or not isinstance(summary, dict):
        raise GuestNICImportError("Missing preview plan")
    if len(plan) != expected_nics or summary.get("vm_count") != expected_vms:
        raise GuestNICImportError("Incorrect VM or interface count")
    if (summary.get("vnic_count") != expected_nics or
            summary.get("create_vm_interface") != expected_nics or
            summary.get("already_present") != 0 or
            summary.get("mac_eligible_after_review") != expected_macs or
            summary.get("mac_held") != len(held)):
        raise GuestNICImportError("Preview is not the approved empty-interface baseline")
    if expected_nics != expected_vms or expected_macs + len(held) != expected_nics:
        raise GuestNICImportError("Unapproved topology or MAC count")

    mac_to_items = defaultdict(list)
    seen_pairs, vms, to_hold = set(), set(), set()
    for row in plan:
        if not isinstance(row, dict):
            raise GuestNICImportError("Malformed preview row")
        vmid = _integer(row.get("vmid"))
        vm_pk = _integer(row.get("netbox_vm_id"))
        name = row.get("vm_interface_name")
        key = row.get("proxmox_config_key")
        bridge = row.get("proxmox_bridge")
        mac = row.get("mac")
        action = row.get("action")
        mac_action = row.get("mac_action")
        if (vmid <= 0 or vm_pk <= 0 or
                not isinstance(name, str) or not VALID_NAME.fullmatch(name) or
                not isinstance(key, str) or not re.fullmatch(r"net[0-9]+", key) or
                not isinstance(bridge, str) or not VALID_BRIDGE.fullmatch(bridge) or
                not isinstance(mac, str) or not VALID_MAC.fullmatch(mac) or
                mac == "00:00:00:00:00:00" or int(mac[:2], 16) & 1 or
                action != "create_vm_interface" or
                mac_action not in ("eligible_after_review", "hold_duplicate_mac")):
            raise GuestNICImportError("Invalid interface row or MAC")
        if (vmid, name) in seen_pairs or vmid in vms:
            raise GuestNICImportError("Duplicate VMID or interface in baseline")
        seen_pairs.add((vmid, name))
        vms.add(vmid)
        mac_to_items[mac].append(row)
        if mac_action == "hold_duplicate_mac":
            to_hold.add(vmid)

    if len(vms) != expected_vms or to_hold != held:
        raise GuestNICImportError("VMID or MAC hold set does not match approval")
    for mac, items in mac_to_items.items():
        if len(items) == 1:
            if items[0]["mac_action"] != "eligible_after_review":
                raise GuestNICImportError("Unexpected MAC hold without duplicate")
        elif len(items) == 2:
            one_held = sum(i["mac_action"] == "hold_duplicate_mac" for i in items)
            if one_held != 1 or any(i["vmid"] not in held for i in items
                                   if i["mac_action"] == "hold_duplicate_mac"):
                raise GuestNICImportError("Unsafe duplicate MAC resolution")
        else:
            raise GuestNICImportError("Unexpected duplicate MAC count")

    warnings = report.get("warnings")
    if not isinstance(warnings, list):
        raise GuestNICImportError("Missing preview warnings")
    if any(not isinstance(w, dict) for w in warnings):
        raise GuestNICImportError("Malformed preview warnings")
    duplicate_warnings = [w for w in warnings if w.get("type") == "duplicate_mac"]
    for mac, items in mac_to_items.items():
        if len(items) > 1:
            ids = sorted(i["vmid"] for i in items)
            if not any(w.get("vmids") == ids for w in duplicate_warnings):
                raise GuestNICImportError("Duplicate MAC warning not present")
    if set(w.get("type") for w in warnings) - {
            "duplicate_mac", "bridge_not_found"}:
        raise GuestNICImportError("Unknown preview warnings; review again")

    return sorted(plan, key=lambda r: (r["vmid"], r["vm_interface_name"]))


def reconcile(plan, *, cluster, expected_vms, apply=False):
    """Revalidate current NetBox ORM state and optionally commit once."""
    from django.db import transaction
    from dcim.models import MACAddress
    from virtualization.models import VirtualMachine, VMInterface

    with transaction.atomic():
        qs = VirtualMachine.objects.filter(
            cluster__name=cluster).order_by("pk")
        vms = list(qs.select_for_update() if apply else qs)
        if len(vms) != expected_vms:
            raise GuestNICImportError("NetBox cluster VM count changed")
        by_pk = {vm.pk: vm for vm in vms}
        by_vmid = {}
        for vm in vms:
            cf = vm.custom_field_data or {}
            try:
                vmid = int(cf["proxmox_vmid"])
            except (KeyError, ValueError, TypeError):
                raise GuestNICImportError("NetBox VMID missing") from None
            if vmid in by_vmid:
                raise GuestNICImportError("Duplicate VMID in NetBox")
            by_vmid[vmid] = vm
        expected_ids = {row["vmid"] for row in plan}
        if set(by_vmid) != expected_ids:
            raise GuestNICImportError("NetBox VMID membership changed")
        for row in plan:
            vm = by_vmid[row["vmid"]]
            if vm.pk != row["netbox_vm_id"]:
                raise GuestNICImportError("VMID to NetBox object mapping changed")

        iq = VMInterface.objects.filter(
            virtual_machine_id__in=list(by_pk)).order_by("pk")
        interfaces = list(iq.select_for_update() if apply else iq)
        if interfaces:
            raise GuestNICImportError("Existing NetBox VM interfaces; rerun preview")
        macs = [row["mac"] for row in plan
                if row["mac_action"] == "eligible_after_review"]
        # Conservative: refuse reusing any pre-existing MACAddress record,
        # regardless of assignment, to prevent an unintended takeover.
        mq = MACAddress.objects.filter(mac_address__in=macs)
        conflicts = list(mq.select_for_update() if apply else mq)
        if conflicts:
            raise GuestNICImportError("Planned guest MAC already exists in NetBox")
        if not apply:
            return {"mode": "DRY-RUN", "matched_vms": len(vms),
                    "create_vm_interfaces": len(plan),
                    "mac_addresses_to_assign": len(macs),
                    "mac_addresses_held": len(plan) - len(macs),
                    "netbox_writes": 0}

        created = {}
        for row in plan:
            suffix = "; base-image MAC held" if row["mac_action"] == "hold_duplicate_mac" else ""
            desc = f"Proxmox host bridge: {row['proxmox_bridge']}{suffix}"
            iface = VMInterface(
                virtual_machine=by_vmid[row["vmid"]],
                name=row["vm_interface_name"],
                description=desc[:200],
            )
            iface.full_clean()
            iface.save()
            created[(row["vmid"], row["vm_interface_name"])] = iface

        for row in plan:
            if row["mac_action"] != "eligible_after_review":
                continue
            iface = created[(row["vmid"], row["vm_interface_name"])]
            iface.set_primary_mac_address_from_value(row["mac"])

        for row in plan:
            iface = VMInterface.objects.get(
                virtual_machine=by_vmid[row["vmid"]],
                name=row["vm_interface_name"])
            if row["mac_action"] == "eligible_after_review":
                if (not iface.primary_mac_address_id or
                    str(iface.primary_mac_address.mac_address).lower() != row["mac"]):
                    raise GuestNICImportError("Assigned MAC verification failed")
            elif iface.primary_mac_address_id is not None:
                raise GuestNICImportError("Held template MAC was unexpectedly assigned")
        if VMInterface.objects.filter(virtual_machine_id__in=list(by_pk)).count() != len(plan):
            raise GuestNICImportError("Created interface count mismatch")
        return {"mode": "APPLY", "matched_vms": len(vms),
                "created_vm_interfaces": len(plan),
                "mac_addresses_assigned": len(macs),
                "mac_addresses_held": len(plan) - len(macs)}


def run(path, *, cluster, expected_vms, expected_nics,
        expected_macs, held_vmids, apply=False,
        confirmation="", freshness_seconds=3600):
    """NetBox manage.py shell entrypoint; no automatic writes by default.

    Requires an independently verified PostgreSQL backup before apply.
    """
    if apply and confirmation != CONFIRM:
        raise GuestNICImportError("Explicit confirmation required for apply")
    with Path(path).open(encoding="utf-8") as stream:
        report = json.load(stream)
    plan = verify_preview(
        report, cluster=cluster, expected_vms=expected_vms,
        expected_nics=expected_nics, expected_macs=expected_macs,
        expected_held=held_vmids, freshness_seconds=freshness_seconds)
    result = reconcile(plan, cluster=cluster, expected_vms=expected_vms,
                       apply=apply)
    for key, value in result.items():
        print(f"{key}: {value}")
    return result
