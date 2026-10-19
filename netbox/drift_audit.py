#!/usr/bin/env python3
"""Proxmox -> NetBox 4.7 read-only daily drift audit.

No NetBox writes: urllib Request(method="GET") only.
Sensitive inventory is stored locally (0600); report never contains raw MACs,
serials, IP addresses, or authentication secrets.

Exit codes: 0 clean, 1 drift detected, 2 collection/API/configuration error.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import ssl
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlsplit
from urllib.request import build_opener, HTTPSHandler, HTTPRedirectHandler, Request

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from collectors.proxmox_inventory import (  # noqa: E402
    PveshClient, collect, save_json,
)

SAFE_NODE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
SAFE_SLUG = re.compile(r"^[a-z0-9_-]{1,100}$")
MAC = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")


class AuditError(RuntimeError):
    """Unexpected or unavailable source data; do not misreport as clean."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise AuditError("HTTPS redirect refused")


class NetBoxReadOnly:
    """Only GETs against the configured origin and /api/dcim/ paths."""

    def __init__(self, url: str, token: str, ca_file: str | None = None):
        split = urlsplit(url)
        if (split.scheme != "https" or not split.hostname or
                split.username or split.password or split.query or split.fragment or
                split.path not in ("", "/")):
            raise AuditError("NetBox URL must be https://hostname[:port]")
        if (not isinstance(token, str) or
                not re.fullmatch(r"nbt_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token)):
            raise AuditError("A NetBox v2 read-only API token is required")
        self.origin = "https://" + split.netloc
        context = ssl.create_default_context(cafile=ca_file)
        self.opener = build_opener(HTTPSHandler(context=context), NoRedirect())
        self.authorization = "Bearer " + token

    def listing(self, endpoint: str, params: dict | None = None) -> list[dict]:
        if not endpoint.startswith("/api/dcim/") or not endpoint.endswith("/"):
            raise AuditError("Forbidden API endpoint")
        query = urlencode(params or {})
        current = self.origin + endpoint + ("?" + query if query else "")
        result: list[dict] = []
        seen: set[str] = set()
        for _ in range(100):
            parsed = urlsplit(current)
            if (parsed.scheme != "https" or
                    ("https://" + parsed.netloc) != self.origin or
                    not parsed.path.startswith("/api/dcim/") or
                    current in seen):
                raise AuditError("Unsafe NetBox pagination response")
            seen.add(current)
            request = Request(current, method="GET", headers={
                "Authorization": self.authorization,
                "Accept": "application/json",
            })
            try:
                with self.opener.open(request, timeout=15) as response:
                    payload = json.load(response)
            except (OSError, HTTPError, URLError, ValueError) as exc:
                # Never expose URLs (which may include internal information),
                # token, response body, or request headers in logs.
                raise AuditError("NetBox HTTPS GET failed") from exc
            if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
                raise AuditError("Malformed NetBox API response")
            result.extend(payload["results"])
            nxt = payload.get("next")
            if nxt is None:
                return result
            if not isinstance(nxt, str):
                raise AuditError("Malformed NetBox pagination next link")
            current = urljoin(self.origin + "/", nxt)
        raise AuditError("NetBox pagination safety limit exceeded")


def nested_slug(obj: dict, key: str) -> str | None:
    value = obj.get(key)
    return value.get("slug") if isinstance(value, dict) else None


def normalized_mac(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    result = value.strip().lower().replace("-", ":")
    return result if MAC.fullmatch(result) else None


def netbox_interface_mac(item: dict) -> str | None:
    """Use NetBox 4.7 mac_address property, or primary_mac_address object."""
    if "mac_address" in item:
        value = item["mac_address"]
        if value is None:
            return None
        if isinstance(value, str):
            result = normalized_mac(value)
            if result:
                return result
    if "primary_mac_address" in item:
        value = item["primary_mac_address"]
        if value is None:
            return None
        if isinstance(value, dict):
            result = normalized_mac(value.get("mac_address"))
            if result:
                return result
    raise AuditError("NetBox interface MAC value missing or unsupported")


def verified_inventory(source: dict) -> list[dict]:
    if not isinstance(source, dict) or source.get("schema_version") != "0.3":
        raise AuditError("Unsupported inventory schema")
    s = source.get("summary")
    nodes = source.get("nodes")
    if (not isinstance(s, dict) or not isinstance(nodes, list) or
            not isinstance(s.get("selected"), int) or
            not isinstance(s.get("collected"), int) or s["selected"] < 1 or
            s["selected"] != s["collected"] or len(nodes) != s["selected"] or
            s.get("errors") != 0 or source.get("errors")):
        raise AuditError("Incomplete Proxmox collection")
    known: set[str] = set()
    for node in nodes:
        if not isinstance(node, dict) or not isinstance(node.get("name"), str):
            raise AuditError("Malformed Proxmox node")
        if not SAFE_NODE.fullmatch(node["name"]) or node["name"] in known:
            raise AuditError("Unexpected or duplicate node name")
        known.add(node["name"])
        if not isinstance(node.get("network_interfaces"), list):
            raise AuditError("Missing Proxmox interface list")
        if (node.get("network_audit") or {}).get("topology_consistent") is not True:
            raise AuditError("Proxmox topology check failed")
    return nodes


def detect_drift(source: dict, client, site_slug: str,
                 role_slug: str, expected_nodes: int) -> dict:
    """Compare only physical-node presence, interface names, serial and NIC MAC.

    Differences omit values, so reports are safe for restricted journaling.
    """
    if not SAFE_SLUG.fullmatch(site_slug) or not SAFE_SLUG.fullmatch(role_slug):
        raise AuditError("Invalid NetBox site or role slug")
    if expected_nodes < 1:
        raise AuditError("Expected node count must be positive")
    nodes = verified_inventory(source)
    differences: list[dict] = []
    counters = Counter()
    if len(nodes) != expected_nodes:
        differences.append({"kind": "node_count_changed", "object": "cluster"})

    for node in nodes:
        name = node["name"]
        lookup = client.listing("/api/dcim/devices/", {"name": name, "limit": 100})
        matches = [device for device in lookup
                   if isinstance(device, dict) and device.get("name") == name]
        if not matches:
            differences.append({"kind": "device_missing", "object": name})
            continue
        if len(matches) != 1:
            differences.append({"kind": "device_ambiguous", "object": name})
            continue
        device = matches[0]
        if (nested_slug(device, "site") != site_slug or
                nested_slug(device, "role") != role_slug):
            differences.append({"kind": "device_mapping_changed", "object": name})
            continue
        if not isinstance(device.get("id"), int):
            raise AuditError("Missing NetBox device identifier")
        source_serial = (node.get("dmi") or {}).get("serial_number")
        if source_serial:
            if not isinstance(source_serial, str):
                raise AuditError("Malformed source serial")
            counters["serials_checked"] += 1
            if not device.get("serial"):
                differences.append({"kind": "serial_missing", "object": name})
            elif device["serial"].strip() != source_serial.strip():
                differences.append({"kind": "serial_mismatch", "object": name})
        else:
            counters["serials_unavailable_source"] += 1

        records = client.listing("/api/dcim/interfaces/",
                                 {"device_id": device["id"], "limit": 500})
        netbox_ifaces = {}
        for record in records:
            if not isinstance(record, dict) or not isinstance(record.get("name"), str):
                raise AuditError("Malformed interface API response")
            if record["name"] in netbox_ifaces:
                raise AuditError("Duplicate NetBox interface name")
            netbox_ifaces[record["name"]] = record

        source_ifaces = {}
        for record in node["network_interfaces"]:
            if not isinstance(record, dict) or not isinstance(record.get("name"), str):
                raise AuditError("Malformed source interface record")
            if record["name"] in source_ifaces:
                raise AuditError("Duplicate Proxmox interface name")
            source_ifaces[record["name"]] = record

        for nic in sorted(set(source_ifaces) - set(netbox_ifaces)):
            differences.append({"kind": "interface_missing", "object": name,
                                "interface": nic})
        for nic in sorted(set(netbox_ifaces) - set(source_ifaces)):
            differences.append({"kind": "interface_extra", "object": name,
                                "interface": nic})

        for nic in sorted(set(source_ifaces) & set(netbox_ifaces)):
            entry = source_ifaces[nic]
            if entry.get("type") != "eth" or not entry.get("mac_address"):
                continue
            expected_mac = normalized_mac(entry["mac_address"])
            if expected_mac is None:
                raise AuditError("Malformed source physical MAC")
            counters["physical_macs_checked"] += 1
            found = netbox_interface_mac(netbox_ifaces[nic])
            if found is None:
                differences.append({"kind": "mac_missing", "object": name,
                                    "interface": nic})
            elif found != expected_mac:
                differences.append({"kind": "mac_mismatch", "object": name,
                                    "interface": nic})

        counters["interfaces_source"] += len(source_ifaces)
        counters["interfaces_netbox"] += len(netbox_ifaces)
        counters["devices_checked"] += 1

    return {
        "schema_version": "0.1",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "status": "drift" if differences else "clean",
        "counts": {**dict(counters), "source_nodes": len(nodes),
                   "expected_nodes": expected_nodes, "differences": len(differences)},
        "by_kind": dict(sorted(Counter(d["kind"] for d in differences).items())),
        "differences": differences,
        "api_methods": ["GET"],
        "netbox_writes": 0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only Proxmox/NetBox daily drift audit")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, help="Test an existing JSON snapshot; omit for live pvesh+SSH")
    parser.add_argument("--cluster-label", default="corporate-pve")
    parser.add_argument("--site-slug", required=True)
    parser.add_argument("--role-slug", required=True)
    parser.add_argument("--expected-nodes", type=int, default=9)
    args = parser.parse_args(argv)

    try:
        client = NetBoxReadOnly(
            os.environ.get("NETBOX_URL", ""),
            os.environ.get("NETBOX_TOKEN", ""),
            os.environ.get("NETBOX_CA_FILE") or None,
        )
        args.output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        if args.inventory:
            with args.inventory.open(encoding="utf-8") as file:
                source = json.load(file)
        else:
            source = collect(PveshClient(), include_remote_dmi=True,
                             include_remote_macs=True,
                             cluster_label=args.cluster_label)
            save_json(source, args.output_dir / "source-latest.json")

        report = detect_drift(source, client, args.site_slug,
                              args.role_slug, args.expected_nodes)
        save_json(report, args.output_dir / "drift-latest.json")
        print("STATUS:", report["status"].upper())
        print("COUNTS:", report["counts"])
        print("DRIFT CATEGORIES:", report["by_kind"])
        print("REPORT:", args.output_dir / "drift-latest.json")
        return 1 if report["status"] == "drift" else 0
    except Exception as exc:
        # No traceback or raw error text: urllib exceptions can expose API URLs.
        print("STATUS: ERROR; reason:", type(exc).__name__, file=sys.stderr)
        try:
            failure = {"status": "error", "checked_at": datetime.now(timezone.utc).isoformat(),
                       "error_type": type(exc).__name__, "netbox_writes": 0}
            save_json(failure, args.output_dir / "drift-latest.json")
        except OSError:
            pass
        return 2


if __name__ == "__main__":
    sys.exit(main())
