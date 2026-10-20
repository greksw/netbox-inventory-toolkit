#!/usr/bin/env python3
"""Read-only QEMU/LXC configuration inventory from a Proxmox VE cluster.

Reads a guest list and each VM/CT config with pvesh GET only. Only whitelisted
fields are retained: ID, type, placement, power, configured CPU, memory and
NIC metadata. Guest disks, passwords, SSH keys, IPs and full configs are never
written. Saved JSON contains private identifiers and has mode 0600.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from collectors.proxmox_inventory import save_json, normalize_mac

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
NET_KEY_RE = re.compile(r"^net([0-9]+)$")
BRIDGE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
SUPPORTED = {"qemu", "lxc"}


class GuestInventoryError(RuntimeError):
    pass


def positive_int(value):
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise GuestInventoryError("Invalid numeric configuration value")
    try:
        parsed = int(value)
    except (ValueError, TypeError, OverflowError) as exc:
        raise GuestInventoryError("Invalid numeric configuration value") from exc
    if parsed <= 0:
        raise GuestInventoryError("Non-positive numeric configuration value")
    return parsed


def vlan_tag(value):
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise GuestInventoryError("Invalid VLAN tag")
    try:
        tag = int(value)
    except (ValueError, TypeError) as exc:
        raise GuestInventoryError("Invalid VLAN tag") from exc
    if not 1 <= tag <= 4094:
        raise GuestInventoryError("Invalid VLAN tag")
    return tag


def guest_identity(row):
    if not isinstance(row, dict):
        raise GuestInventoryError("Malformed guest list")
    vmid = positive_int(row.get("vmid"))
    kind = row.get("type")
    node = row.get("node")
    status = row.get("status")
    if (vmid is None or vmid > 999999999 or kind not in SUPPORTED or
            not isinstance(node, str) or not NAME_RE.fullmatch(node) or
            not isinstance(status, str) or status not in ("running", "stopped")):
        raise GuestInventoryError("Incomplete guest identity/placement/status")
    return vmid, kind, node, status


def nic_info(key, raw, kind):
    if not isinstance(raw, str):
        raise GuestInventoryError("Malformed guest NIC configuration")
    parts = raw.split(",")
    values = {}
    for part in parts:
        k, sep, v = part.partition("=")
        if sep and k and k not in values:
            values[k.strip()] = v.strip()
    entry = {"key": key}
    if kind == "qemu":
        models = [
            model for model in ("virtio", "e1000", "e1000-82545em",
                                "e1000-82540em", "rtl8139", "vmxnet3",
                                "ne2k_pci", "i82551", "i82557b", "i82559er")
            if model in values
        ]
        # Preserve unknown model as unknown; never infer a physical NIC.
        if models:
            entry["model"] = models[0]
            entry["mac"] = normalize_mac(values[models[0]])
    else:
        if values.get("name"):
            entry["name"] = values["name"]
        entry["mac"] = normalize_mac(values.get("hwaddr"))
    bridge = values.get("bridge")
    if bridge:
        if not BRIDGE_RE.fullmatch(bridge):
            raise GuestInventoryError("Unexpected bridge format")
        entry["bridge"] = bridge
    tag = vlan_tag(values.get("tag"))
    if tag is not None:
        entry["vlan_tag"] = tag
    return entry


def normalize_guest(summary, config):
    vmid, kind, node, status = guest_identity(summary)
    if not isinstance(config, dict):
        raise GuestInventoryError("Malformed per-guest config")
    sockets = positive_int(config.get("sockets")) if kind == "qemu" else None
    cores = positive_int(config.get("cores"))
    memory = positive_int(config.get("memory"))
    # For QEMU this is configured maximum vCPU topology, NOT real-time CPU use.
    configured_vcpus = (sockets * cores if sockets is not None and cores is not None
                         else cores if kind == "lxc" else None)
    entries = []
    for key, value in config.items():
        if isinstance(key, str) and NET_KEY_RE.fullmatch(key):
            entries.append(nic_info(key, value, kind))
    entries.sort(key=lambda item: int(item["key"][3:]))
    return {
        "vmid": vmid, "type": kind,
        "name": str(summary.get("name") or ""), "node": node,
        "power_state": status,
        "cpu": {"sockets": sockets, "cores": cores,
                "configured_max_vcpus": configured_vcpus},
        "memory_mib": memory,
        "interfaces": entries,
    }


class PveshGuestClient:
    """Uses pvesh get only. No POST, SET or DELETE operations."""

    def _execute(self, argv):
        try:
            p = subprocess.run(
                argv, capture_output=True, text=True, timeout=45, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GuestInventoryError("pvesh GET failed") from exc
        if p.returncode:
            # Do not log raw stderr/stdout: configuration errors may reveal paths.
            raise GuestInventoryError("pvesh GET returned an error")
        try:
            return json.loads(p.stdout)
        except (ValueError, TypeError) as exc:
            raise GuestInventoryError("Invalid JSON from pvesh GET") from exc

    def resources(self):
        result = self._execute([
            "pvesh", "get", "/cluster/resources", "--type", "vm",
            "--output-format", "json",
        ])
        if not isinstance(result, list):
            raise GuestInventoryError("Unexpected cluster resource response")
        return result

    def configuration(self, node, kind, vmid):
        return self._execute([
            "pvesh", "get", f"/nodes/{node}/{kind}/{vmid}/config",
            "--output-format", "json",
        ])


def collect(client, *, expected_guests=None, cluster_label=None):
    """Fail closed if guest membership, placement or status changes mid-scan."""
    begin = client.resources()
    identities = {}
    for entry in begin:
        ident = guest_identity(entry)
        vmid = ident[0]
        if vmid in identities:
            raise GuestInventoryError("Duplicate VMID in Proxmox cluster")
        identities[vmid] = (ident, entry)
    if not identities:
        raise GuestInventoryError("Empty Proxmox guest collection")
    if expected_guests is not None and len(identities) != expected_guests:
        raise GuestInventoryError("Unexpected number of Proxmox guests")

    guests = []
    for vmid in sorted(identities):
        (id_, kind, node, status), entry = identities[vmid]
        try:
            raw = client.configuration(node, kind, vmid)
            guests.append(normalize_guest(entry, raw))
        except GuestInventoryError as exc:
            raise GuestInventoryError(f"Guest {vmid}: {exc}") from None

    end = client.resources()
    ending = {}
    for entry in end:
        ident = guest_identity(entry)
        if ident[0] in ending:
            raise GuestInventoryError("Duplicate VMID in final cluster snapshot")
        ending[ident[0]] = ident
    if ending != {vmid: record[0] for vmid, record in identities.items()}:
        raise GuestInventoryError("Cluster changed during collection; retry")
    nic_count = sum(len(v["interfaces"]) for v in guests)
    return {
        "schema_version": "guests-0.1",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "source": {"tool": "pvesh", "cluster_label": cluster_label},
        "guests": guests,
        "summary": {
            "selected": len(identities),
            "collected": len(guests),
            "by_type": dict(sorted(Counter(g["type"] for g in guests).items())),
            "by_power": dict(sorted(Counter(g["power_state"] for g in guests).items())),
            "interfaces": nic_count,
            "nics_without_mac": sum(
                1 for guest in guests for nic in guest["interfaces"] if not nic.get("mac")),
            "guests_without_memory": sum(g["memory_mib"] is None for g in guests),
            "guests_without_cpu": sum(g["cpu"]["configured_max_vcpus"] is None for g in guests),
            "errors": 0,
        },
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--expected-guests", type=int)
    p.add_argument("--cluster-label", default="corporate-pve")
    p.add_argument("--output", type=Path,
                   default=Path("output/proxmox-guests-v01.json"))
    args = p.parse_args(argv)
    if args.expected_guests is not None and args.expected_guests <= 0:
        p.error("--expected-guests must be positive")
    try:
        inventory = collect(PveshGuestClient(),
                            expected_guests=args.expected_guests,
                            cluster_label=args.cluster_label)
        save_json(inventory, args.output)
    except (GuestInventoryError, OSError) as exc:
        print("ERROR:", str(exc), file=sys.stderr)
        return 2
    summary = inventory["summary"]
    print(
        f"Saved {args.output}: guests={summary['collected']} "
        f"types={summary['by_type']} power={summary['by_power']} "
        f"vNICs={summary['interfaces']} missing_MAC={summary['nics_without_mac']} "
        f"missing_CPU={summary['guests_without_cpu']} "
        f"missing_RAM={summary['guests_without_memory']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
