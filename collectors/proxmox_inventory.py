#!/usr/bin/env python3
"""Read-only Proxmox VE node/network inventory. No NetBox writes.

Requires Python >=3.9 on a Proxmox VE cluster node and root for `pvesh`.
Only documented `pvesh get` calls are executed; optional SSH reads DMI sysfs.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any

NODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
SSH_USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
DMI_KEYS = {
    "sys_vendor": "manufacturer",
    "product_name": "model",
    "product_version": "product_version",
    "board_name": "motherboard",
    "product_serial": "serial_number",
}
DMI_PROBE = (
    'for k in sys_vendor product_name product_version board_name product_serial; do '
    'f="/sys/class/dmi/id/$k"; '
    'if [ -r "$f" ]; then printf "%s=" "$k"; '
    'tr "\\n" " " < "$f"; printf "\\n"; fi; done'
)


INVALID_SERIALS = {
    "", "none", "unknown", "n/a", "not specified",
    "to be filled by o.e.m.", "default string", "system serial number",
}
MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")


def serial_valid(value: str) -> bool:
    return value.strip().casefold() not in INVALID_SERIALS


def normalize_mac(value: Any) -> str | None:
    """Record only a genuine six-octet value explicitly supplied by Proxmox."""
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower().replace("-", ":")
    if not MAC_RE.fullmatch(normalized):
        return None
    first = int(normalized[:2], 16)
    if first & 1 or normalized == "00:00:00:00:00:00":
        return None
    return normalized


def parse_mac_records(output: str) -> dict[str, str]:
    """Parse fixed-format host probe output without trusting arbitrary strings."""
    macs: dict[str, str] = {}
    for line in output.splitlines():
        name, sep, raw_mac = line.partition("=")
        if not sep or not name or "/" in name or name in {".", ".."}:
            continue
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", name):
            continue
        mac = normalize_mac(raw_mac)
        if mac:
            macs[name] = mac
    return macs


def local_physical_nic_macs(root: Path = Path("/sys/class/net")) -> dict[str, str]:
    """Current active MAC, not necessarily the factory-programmed NIC MAC."""
    output: dict[str, str] = {}
    try:
        candidates = list(root.iterdir())
    except OSError as exc:
        raise CollectionError(f"Cannot list physical NICs: {exc}") from exc
    for nic in candidates:
        if not (nic / "device").exists():
            continue
        try:
            mac = normalize_mac((nic / "address").read_text().strip())
        except OSError:
            continue
        if mac:
            output[nic.name] = mac
    return output


PHYSICAL_NIC_PROBE = (
    'for d in /sys/class/net/*; do '
    '[ -e "$d/device" ] || continue; [ -r "$d/address" ] || continue; '
    'printf "%s=" "$(basename "$d")"; cat "$d/address"; done'
)


def remote_physical_nic_macs(node: str, user: str, timeout: int) -> dict[str, str]:
    """Get current MACs of hardware-backed Linux NICs over verified SSH."""
    validate_node(node)
    if not SSH_USER_RE.fullmatch(user):
        raise ValueError("Invalid SSH username")
    try:
        result = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
             "-o", "PasswordAuthentication=no", "-o", f"ConnectTimeout={timeout}",
             "-o", "LogLevel=ERROR", "--", f"{user}@{node}", PHYSICAL_NIC_PROBE],
            capture_output=True, text=True, timeout=timeout + 8, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CollectionError(f"NIC MAC SSH for {node}: {exc}") from exc
    if result.returncode:
        detail = (result.stderr or "SSH failed").strip()[:200]
        raise CollectionError(f"NIC MAC SSH for {node}: {detail}")
    return parse_mac_records(result.stdout)


def merge_physical_macs(node: dict[str, Any], macs: dict[str, str]) -> None:
    """Only annotate NICs whose PVE type is eth; do not assign to VLAN/bridge."""
    for item in node["network_interfaces"]:
        if item.get("type") != "eth":
            continue
        current_mac = macs.get(item["name"])
        if current_mac:
            item["mac_address"] = current_mac
    node["network_audit"] = audit_network(node["network_interfaces"])


def link_names(value: Any) -> list[str]:
    """Split Proxmox interface references without guessing physical topology."""
    if not isinstance(value, str):
        return []
    return [name for name in re.split(r"[\s,]+", value.strip())
            if name and name.lower() != "none"]


def audit_network(interfaces: list[dict[str, Any]]) -> dict[str, Any]:
    """Non-destructive topology validation. Warnings demand human review."""
    known = {item["name"] for item in interfaces}
    issues: list[dict[str, str]] = []
    vlan_total = vlan_ids = vlan_parents = bridges = bridges_with_ports = 0
    ipv4_count = ipv6_count = mac_count = 0

    def issue(iface: str, code: str, reference: str = "") -> None:
        issues.append({"interface": iface, "code": code, "reference": reference})

    if len(known) != len(interfaces):
        issue("", "duplicate_interface_name")
    for item in interfaces:
        name = item["name"]
        kind = item.get("type")
        ipv4_count += int(bool(item.get("ipv4_cidr")))
        ipv6_count += int(bool(item.get("ipv6_cidr")))
        mac_count += int(bool(item.get("mac_address")))
        if kind == "vlan":
            vlan_total += 1
            vlan_id = maybe_int(item.get("vlan_id"))
            if vlan_id is not None and 1 <= vlan_id <= 4094:
                vlan_ids += 1
            else:
                issue(name, "vlan_id_missing_or_invalid")
            parent = item.get("vlan_raw_device")
            if isinstance(parent, str) and parent.strip():
                vlan_parents += 1
                if parent.strip() not in known:
                    issue(name, "vlan_parent_not_found", parent.strip())
            else:
                issue(name, "vlan_parent_missing")
        if kind == "bridge":
            bridges += 1
            ports = link_names(item.get("bridge_ports"))
            bridges_with_ports += int(bool(ports))
            for port in ports:
                if port not in known:
                    issue(name, "bridge_port_not_found", port)
        if kind == "bond":
            for slave in link_names(item.get("slaves")):
                if slave not in known:
                    issue(name, "bond_slave_not_found", slave)
    return {
        "interface_count": len(interfaces),
        "ipv4_count": ipv4_count,
        "ipv6_count": ipv6_count,
        "mac_count": mac_count,
        "vlan_count": vlan_total,
        "vlan_with_id_count": vlan_ids,
        "vlan_with_parent_count": vlan_parents,
        "bridge_count": bridges,
        "bridge_with_ports_count": bridges_with_ports,
        "topology_consistent": not issues,
        "topology_issues": issues,
    }


class CollectionError(Exception):
    """Non-fatal problem with a single API query or node."""


def validate_node(node: str) -> str:
    if not NODE_RE.fullmatch(node) or node in {".", ".."}:
        raise ValueError(f"Invalid node name: {node!r}")
    return node


class PveshClient:
    def get(self, path: str) -> Any:
        result = subprocess.run(
            ["pvesh", "get", path, "--output-format", "json"],
            capture_output=True, text=True, timeout=45, check=False,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()[:500]
            raise CollectionError(f"pvesh {path}: {detail or 'command failed'}")
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise CollectionError(f"pvesh {path}: malformed JSON") from exc


def local_dmi() -> dict[str, str]:
    result = {}
    for filename, field in DMI_KEYS.items():
        try:
            value = (Path("/sys/class/dmi/id") / filename).read_text().strip()
        except (PermissionError, FileNotFoundError, OSError):
            continue
        if value and (field != "serial_number" or serial_valid(value)):
            result[field] = value
    return result


def remote_dmi(node: str, user: str, timeout: int) -> dict[str, str]:
    validate_node(node)
    if not SSH_USER_RE.fullmatch(user):
        raise ValueError("Invalid SSH username")
    try:
        result = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
             "-o", "PasswordAuthentication=no", "-o", f"ConnectTimeout={timeout}",
             "-o", "LogLevel=ERROR", "--", f"{user}@{node}", DMI_PROBE],
            capture_output=True, text=True, timeout=timeout + 8, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CollectionError(f"DMI SSH for {node}: {exc}") from exc
    if result.returncode:
        raise CollectionError(f"DMI SSH for {node}: {(result.stderr or 'SSH failed').strip()[:200]}")
    parsed = {}
    for line in result.stdout.splitlines():
        key, sep, value = line.partition("=")
        if sep and key in DMI_KEYS and value.strip():
            field = DMI_KEYS[key]
            if field != "serial_number" or serial_valid(value):
                parsed[field] = value.strip()
    return parsed


def maybe_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (ValueError, TypeError, OverflowError):
        return None


def normalized_cidr(address: Any, mask: Any) -> str | None:
    if not isinstance(address, str) or not address:
        return None
    try:
        if "/" in address:
            return str(ipaddress.ip_interface(address))
        if mask is None or mask == "":
            return None
        return str(ipaddress.ip_interface(f"{address}/{mask}"))
    except ValueError:
        return None


def normalize_interface(record: dict[str, Any]) -> dict[str, Any]:
    fields = (
        "type", "active", "autostart", "method", "method6", "mtu", "gateway",
        "gateway6", "bridge_ports", "bridge_vlan_aware", "bridge_vids", "slaves",
        "bond_mode", "bond_xmit_hash_policy", "vlan-id", "vlan-raw-device",
        "ovs_bridge", "ovs_ports",
    )
    normalized = {"name": str(record["iface"])}
    for field in fields:
        val = record.get(field)
        if val is not None and val != "":
            normalized[field.replace("-", "_")] = val
    for key in ("hwaddress", "hwaddr", "mac", "mac_address"):
        mac = normalize_mac(record.get(key))
        if mac:
            normalized["mac_address"] = mac
            break
    v4 = normalized_cidr(record.get("cidr") or record.get("address"), record.get("netmask"))
    v6 = normalized_cidr(record.get("cidr6") or record.get("address6"), record.get("netmask6"))
    if v4:
        normalized["ipv4_cidr"] = v4
    if v6:
        normalized["ipv6_cidr"] = v6
    return normalized


def normalize_node(name: str, status: dict[str, Any], network: list[dict[str, Any]],
                   dmi: dict[str, str] | None = None) -> dict[str, Any]:
    validate_node(name)
    cpu = status.get("cpuinfo") if isinstance(status.get("cpuinfo"), dict) else {}
    memory = status.get("memory") if isinstance(status.get("memory"), dict) else {}
    interfaces = [normalize_interface(item) for item in network if isinstance(item, dict)
                  and isinstance(item.get("iface"), str) and item["iface"]]
    interfaces.sort(key=lambda item: item["name"])
    result: dict[str, Any] = {
        "name": name,
        "cpu": {
            "model": cpu.get("model"),
            "sockets": maybe_int(cpu.get("sockets")),
            "cores": maybe_int(cpu.get("cores")),
            "threads": maybe_int(cpu.get("cpus", status.get("maxcpu"))),
        },
        "memory_total_bytes": maybe_int(memory.get("total", status.get("maxmem"))),
        "network_interfaces": interfaces,
        "network_audit": audit_network(interfaces),
    }
    if dmi:
        result["dmi"] = dmi
    return result


def collect(client: PveshClient, requested: list[str] | None = None,
            include_remote_dmi: bool = False, include_remote_macs: bool = False,
            ssh_user: str = "root", ssh_timeout: int = 5,
            cluster_label: str | None = None, local_name: str | None = None) -> dict[str, Any]:
    """Return a complete report. Node failures appear in errors and are not silently dropped."""
    discovered = client.get("/nodes")
    if not isinstance(discovered, list):
        raise CollectionError("/nodes: expected JSON array")
    known = {item["node"] for item in discovered if isinstance(item, dict)
             and isinstance(item.get("node"), str) and NODE_RE.fullmatch(item["node"])}
    wanted = sorted(set(map(validate_node, requested))) if requested else sorted(known)
    report: dict[str, Any] = {
        "schema_version": "0.3",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "source": {
            "tool": "pvesh", "cluster_label": cluster_label,
            "collector_host": local_name or socket.gethostname().split(".")[0],
        },
        "nodes": [], "errors": [],
    }
    for name in wanted:
        if name not in known:
            report["errors"].append({"node": name, "stage": "discovery", "error": "not in /nodes"})
            continue
        try:
            status = client.get(f"/nodes/{name}/status")
            network = client.get(f"/nodes/{name}/network")
            if not isinstance(status, dict) or not isinstance(network, list):
                raise CollectionError("Unexpected node status/network JSON shape")
            dmi = None
            if name == (local_name or socket.gethostname().split(".")[0]):
                dmi = local_dmi()
            elif include_remote_dmi:
                try:
                    dmi = remote_dmi(name, ssh_user, ssh_timeout)
                except CollectionError as exc:
                    report["errors"].append({"node": name, "stage": "dmi", "error": str(exc)})
            node_data = normalize_node(name, status, network, dmi)
            if name == (local_name or socket.gethostname().split(".")[0]):
                try:
                    merge_physical_macs(node_data, local_physical_nic_macs())
                except CollectionError as exc:
                    report["errors"].append({"node": name, "stage": "mac", "error": str(exc)})
            elif include_remote_macs:
                try:
                    merge_physical_macs(node_data, remote_physical_nic_macs(name, ssh_user, ssh_timeout))
                except CollectionError as exc:
                    report["errors"].append({"node": name, "stage": "mac", "error": str(exc)})
            report["nodes"].append(node_data)
        except (CollectionError, subprocess.TimeoutExpired, OSError) as exc:
            report["errors"].append({"node": name, "stage": "pvesh", "error": str(exc)[:500]})
    report["summary"] = {
        "selected": len(wanted),
        "collected": len(report["nodes"]),
        "errors": len(report["errors"]),
    }
    report["audit_summary"] = {
        "nodes_with_dmi": sum(bool(n.get("dmi")) for n in report["nodes"]),
        "nodes_with_serial": sum(bool(n.get("dmi", {}).get("serial_number")) for n in report["nodes"]),
        "mac_addresses": sum(n["network_audit"]["mac_count"] for n in report["nodes"]),
        "topology_issues": sum(len(n["network_audit"]["topology_issues"]) for n in report["nodes"]),
        "topology_review_passed": (
            len(report["nodes"]) == len(wanted)
            and not report["errors"]
            and all(n["network_audit"]["topology_consistent"] for n in report["nodes"])
        ),
    }
    return report


def save_json(report: dict[str, Any], output: Path) -> None:
    """Atomic output with owner-only file permissions."""
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmpname = tempfile.mkstemp(prefix=".inventory-", suffix=".tmp", dir=output.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False, sort_keys=True)
            fh.write("\n")
        os.chmod(tmpname, 0o600)
        os.replace(tmpname, output)
    finally:
        if os.path.exists(tmpname):
            os.unlink(tmpname)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only Proxmox node inventory (no NetBox API writes)")
    parser.add_argument("--node", action="append", help="Limit to one node; repeat to select several")
    parser.add_argument("--output", type=Path, default=Path("output/proxmox-inventory.json"))
    parser.add_argument("--cluster-label", help="Optional human-readable cluster label")
    parser.add_argument("--dmi-ssh", action="store_true", help="Read DMI sysfs of remote cluster nodes over SSH")
    parser.add_argument("--mac-ssh", action="store_true", help="Read current MACs for hardware-backed remote NICs over verified SSH")
    parser.add_argument("--ssh-user", default="root")
    parser.add_argument("--ssh-timeout", type=int, default=5)
    args = parser.parse_args(argv)
    if args.ssh_timeout < 1 or args.ssh_timeout > 60 or not SSH_USER_RE.fullmatch(args.ssh_user):
        parser.error("Invalid SSH timeout or SSH username")
    try:
        for node in args.node or []:
            validate_node(node)
        inventory = collect(PveshClient(), requested=args.node,
                            include_remote_dmi=args.dmi_ssh,
                            include_remote_macs=args.mac_ssh,
                            ssh_user=args.ssh_user, ssh_timeout=args.ssh_timeout,
                            cluster_label=args.cluster_label)
        save_json(inventory, args.output)
    except (CollectionError, ValueError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    s = inventory["summary"]
    audit = inventory["audit_summary"]
    print(f"Saved {args.output}: collected={s['collected']}/{s['selected']} errors={s['errors']} "
          f"topology_issues={audit['topology_issues']} serials={audit['nodes_with_serial']} "
          f"macs={audit['mac_addresses']}")
    return 0 if s["errors"] == 0 and s["collected"] > 0 else 2


if __name__ == "__main__":
    sys.exit(main())