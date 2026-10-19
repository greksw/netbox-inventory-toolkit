#!/usr/bin/env python3
"""Guarded NetBox 4.7 hardware reconciliation; invoke run() from manage.py shell.

Only existing devices and interfaces are eligible. No default writes.
Never log raw MAC addresses or hardware serial values.
"""
from __future__ import annotations
import json
import re

class EnrichmentError(RuntimeError):
    pass

def plan_from_inventory(report):
    if not isinstance(report, dict) or report.get("schema_version") != "0.3":
        raise EnrichmentError("Expected inventory schema 0.3")
    summary = report.get("summary", {})
    audit = report.get("audit_summary", {})
    nodes = report.get("nodes")
    if (not isinstance(summary, dict) or
        not isinstance(audit, dict) or
        not isinstance(nodes, list) or
        not isinstance(summary.get("selected"), int) or
        not isinstance(summary.get("collected"), int) or
        summary["selected"] < 1 or
        summary["selected"] != summary["collected"] or
        summary["selected"] != len(nodes) or
        summary.get("errors") != 0 or report.get("errors") or
        audit.get("topology_review_passed") is not True):
        raise EnrichmentError("Incomplete inventory or failed topology audit")
    names, pairs, serials, macs = set(), set(), {}, {}
    for node in nodes:
        if not isinstance(node, dict):
            raise EnrichmentError("Malformed node")
        name = node.get("name")
        if (not isinstance(name, str) or
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", name) or
            name in names):
            raise EnrichmentError("Invalid or duplicate node name")
        names.add(name)
        if not (node.get("network_audit") or {}).get("topology_consistent"):
            raise EnrichmentError("Node topology was not validated")
        dmi = node.get("dmi") or {}
        if not isinstance(dmi, dict):
            raise EnrichmentError("Malformed DMI")
        serial = dmi.get("serial_number")
        if serial:
            if not isinstance(serial, str):
                raise EnrichmentError("Malformed serial")
            serials[name] = serial.strip()
        interfaces = node.get("network_interfaces")
        if not isinstance(interfaces, list):
            raise EnrichmentError("Malformed interfaces")
        for nic in interfaces:
            if not isinstance(nic, dict) or not isinstance(nic.get("name"), str):
                raise EnrichmentError("Malformed interface")
            key = (name, nic["name"])
            if not nic["name"] or key in pairs:
                raise EnrichmentError("Duplicate or empty interface")
            pairs.add(key)
            if nic.get("type") == "eth" and nic.get("mac_address"):
                mac = nic["mac_address"]
                if not isinstance(mac, str):
                    raise EnrichmentError("Malformed MAC")
                mac = mac.strip().lower()
                if (not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac)
                    or mac == "00:00:00:00:00:00"
                    or int(mac[:2], 16) & 1):
                    raise EnrichmentError("Invalid physical MAC")
                macs[key] = mac
    if len(set(s.casefold() for s in serials.values())) != len(serials):
        raise EnrichmentError("Duplicate serials")
    if len(set(macs.values())) != len(macs):
        raise EnrichmentError("Duplicate MACs")
    return {"names": names, "pairs": pairs, "serials": serials, "macs": macs}

def assert_counts(plan, *, devices, interfaces, serials, macs):
    expected = (devices, interfaces, serials, macs)
    actual = (len(plan["names"]), len(plan["pairs"]),
              len(plan["serials"]), len(plan["macs"]))
    if actual != expected:
        raise EnrichmentError("Source counts changed from approved baseline")

def reconcile_in_netbox(plan, site_slug, role_slug, apply=False, confirmation=""):
    if apply and confirmation != "APPLY_EXISTING_HARDWARE_ONLY":
        raise EnrichmentError("Explicit apply confirmation required")
    if not site_slug or not role_slug:
        raise EnrichmentError("Site and role required")
    from django.db import transaction
    from django.contrib.contenttypes.models import ContentType
    from dcim.models import Device, Interface, MACAddress

    with transaction.atomic():
        qs = Device.objects.filter(name__in=plan["names"]).order_by("pk")
        devices = list(qs.select_for_update() if apply else qs)
        dmap = {x.name: x for x in devices}
        if len(devices) != len(plan["names"]) or set(dmap) != plan["names"]:
            raise EnrichmentError("Device identity mismatch")
        for device in devices:
            if device.site.slug != site_slug or device.role.slug != role_slug:
                raise EnrichmentError("Site/role mismatch")

        qs = Interface.objects.filter(
            device_id__in=[d.pk for d in devices]).order_by("pk")
        interfaces = list(qs.select_for_update() if apply else qs)
        names_by_id = {d.pk: d.name for d in devices}
        imap = {(names_by_id[i.device_id], i.name): i for i in interfaces}
        if len(imap) != len(interfaces) or set(imap) != plan["pairs"]:
            raise EnrichmentError("Interface inventory mismatch")

        source_serials = {s.casefold() for s in plan["serials"].values()}
        other_serials = Device.objects.exclude(
            pk__in=[d.pk for d in devices]).exclude(
            serial="").values_list("serial", flat=True)
        if any(s and s.casefold() in source_serials for s in other_serials):
            raise EnrichmentError("Serial belongs to another device")

        serial_changes, mac_changes = [], []
        for name, serial in plan["serials"].items():
            current = (dmap[name].serial or "").strip()
            if not current:
                serial_changes.append((dmap[name], serial))
            elif current != serial:
                raise EnrichmentError("Existing serial conflict")
        for key, mac in plan["macs"].items():
            iface = imap[key]
            existing = iface.primary_mac_address
            if existing is None:
                mac_changes.append((iface, mac))
            elif str(existing.mac_address).lower() != mac:
                raise EnrichmentError("Existing primary MAC conflict")

        ctype = ContentType.objects.get_for_model(Interface)
        macmap = {mac: imap[pair] for pair, mac in plan["macs"].items()}
        qs = MACAddress.objects.filter(mac_address__in=list(macmap))
        for obj in (qs.select_for_update() if apply else qs):
            assigned_iface = macmap.get(str(obj.mac_address).lower())
            if (assigned_iface is None or
                obj.assigned_object_type_id != ctype.pk or
                obj.assigned_object_id != assigned_iface.pk):
                raise EnrichmentError("MAC is assigned elsewhere")

        if apply:
            for device, serial in serial_changes:
                device.snapshot()
                device.serial = serial
                device.full_clean()
                device.save(update_fields=["serial"])
            for iface, mac in mac_changes:
                iface.set_primary_mac_address_from_value(mac)
            for name, serial in plan["serials"].items():
                if Device.objects.get(pk=dmap[name].pk).serial != serial:
                    raise EnrichmentError("Serial verification failed")
            for pair, mac in plan["macs"].items():
                iface = Interface.objects.get(pk=imap[pair].pk)
                if (not iface.primary_mac_address_id or
                    str(iface.primary_mac_address.mac_address).lower() != mac):
                    raise EnrichmentError("MAC verification failed")

    return {"mode": "APPLY" if apply else "DRY-RUN",
            "verified_devices": len(devices),
            "verified_interfaces": len(interfaces),
            "serials_to_add": len(serial_changes),
            "macs_to_assign": len(mac_changes),
            "serials_matching": len(plan["serials"]) - len(serial_changes),
            "macs_matching": len(plan["macs"]) - len(mac_changes)}

def run(path, *, site_slug, role_slug,
        expected_devices, expected_interfaces, expected_serials, expected_macs,
        apply=False, confirmation=""):
    with open(path, encoding="utf-8") as stream:
        report = json.load(stream)
    plan = plan_from_inventory(report)
    assert_counts(plan, devices=expected_devices,
                  interfaces=expected_interfaces, serials=expected_serials,
                  macs=expected_macs)
    result = reconcile_in_netbox(plan, site_slug, role_slug,
                                 apply=apply, confirmation=confirmation)
    for label, value in result.items():
        print(label + ":", value)
    return result
