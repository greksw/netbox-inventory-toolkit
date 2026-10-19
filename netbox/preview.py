#!/usr/bin/env python3
"""Read-only NetBox DCIM preview for Proxmox inventory v0.3; no API writes."""
from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import ssl
import sys
import tempfile
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler
from urllib.error import HTTPError, URLError

NODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,99}$")


class PreviewError(Exception):
    pass


def read_inventory(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or data.get("schema_version") != "0.3":
        raise PreviewError("Expected Proxmox Inventory Toolkit schema v0.3")
    return data


def offline_plan(data: dict) -> dict:
    """Do not infer device types, interface speeds, cabling or IP assignment."""
    nodes = data.get("nodes")
    summary = data.get("summary")
    if not isinstance(nodes, list) or not isinstance(summary, dict):
        raise PreviewError("Invalid inventory nodes/summary")
    blockers = []
    if data.get("errors"):
        blockers.append("collector_errors")
    if not nodes or summary.get("collected") != len(nodes) or summary.get("selected") != len(nodes):
        blockers.append("incomplete_collection")
    seen_names, seen_macs = set(), set()
    totals = Counter()
    devices = []
    for node in nodes:
        if not isinstance(node, dict):
            blockers.append("invalid_node")
            continue
        name = node.get("name")
        if not isinstance(name, str) or not NODE_RE.fullmatch(name) or name in seen_names:
            blockers.append("invalid_or_duplicate_node_name")
            continue
        seen_names.add(name)
        if not (node.get("network_audit") or {}).get("topology_consistent", False):
            blockers.append("topology_not_verified")
        dmi = node.get("dmi") or {}
        manufacturer, model = dmi.get("manufacturer"), dmi.get("model")
        if not manufacturer or not model:
            blockers.append("missing_device_identity")
        interfaces = node.get("network_interfaces")
        if not isinstance(interfaces, list):
            blockers.append("invalid_network_interfaces")
            continue
        if any(not isinstance(i, dict) or not isinstance(i.get("name"), str) for i in interfaces):
            blockers.append("invalid_interface_record")
            continue
        names = [i["name"] for i in interfaces]
        if len(set(names)) != len(names):
            blockers.append("duplicate_interface_name")
        eth = [i for i in interfaces if i.get("type") == "eth"]
        deferred = [i for i in interfaces if i.get("type") != "eth"]
        for iface in eth:
            mac = iface.get("mac_address")
            if mac:
                if mac.lower() in seen_macs:
                    blockers.append("duplicate_current_mac")
                seen_macs.add(mac.lower())
        totals["physical_interfaces"] += len(eth)
        totals["deferred_interfaces"] += len(deferred)
        totals["current_macs"] += sum(bool(i.get("mac_address")) for i in eth)
        totals["serials_present"] += bool(dmi.get("serial_number"))
        totals["deferred_ip_addresses"] += sum(bool(i.get("ipv4_cidr") or i.get("ipv6_cidr")) for i in interfaces)
        devices.append({
            "name": name, "manufacturer": manufacturer, "model": model,
            "serial_present": bool(dmi.get("serial_number")),
            "physical_interface_names": sorted(i["name"] for i in eth),
            "physical_interfaces": len(eth), "deferred_interfaces": len(deferred),
        })
    codes = sorted(set(blockers))
    return {
        "plan_schema": "0.1", "read_only": True,
        "summary": {"devices": len(devices), **dict(totals),
                    "blocking_issue_codes": codes, "ready_to_compare": not codes},
        "devices": sorted(devices, key=lambda d: d["name"]),
        "deferred": ["bridges", "vlan_subinterfaces", "vlans", "ip_addresses",
                     "cables", "qemu_vms", "lxc_containers"],
    }


class RefuseRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise PreviewError("Redirect refused to protect API token")


class ReadOnlyNetBox:
    def __init__(self, url: str, token: str, ca_bundle: str | None = None):
        parts = urlsplit(url)
        if (parts.scheme != "https" or not parts.netloc or not parts.hostname
                or parts.username or parts.password or parts.path not in ("", "/")
                or parts.query or parts.fragment):
            raise PreviewError("Use https://netbox-host[:port] without path")
        if not token.startswith("nbt_") or "." not in token:
            raise PreviewError("Expected NetBox v2 read-only API token (nbt_ prefix)")
        self.origin = f"https://{parts.netloc}"
        self.auth = "Bearer " + token
        self.client = build_opener(HTTPSHandler(context=ssl.create_default_context(cafile=ca_bundle)),
                                   RefuseRedirects())

    def list(self, endpoint: str, filters: dict | None = None) -> list[dict]:
        if not re.fullmatch(r"/api/[a-z0-9/-]+/", endpoint):
            raise PreviewError("Invalid API endpoint")
        query = urlencode(filters or {})
        next_url = self.origin + endpoint + ("?" + query if query else "")
        results = []
        for _ in range(30):
            parts = urlsplit(next_url)
            if f"{parts.scheme}://{parts.netloc}" != self.origin or not parts.path.startswith("/api/"):
                raise PreviewError("Unsafe API pagination URL")
            request = Request(next_url, headers={"Authorization": self.auth,
                                                  "Accept": "application/json"}, method="GET")
            try:
                with self.client.open(request, timeout=15) as response:
                    obj = json.load(response)
            except (HTTPError, URLError, OSError, TimeoutError, ValueError) as exc:
                raise PreviewError(f"NetBox GET failed ({type(exc).__name__}); check TLS, token and permissions") from exc
            if not isinstance(obj, dict) or not isinstance(obj.get("results"), list):
                raise PreviewError("Unexpected NetBox response type")
            results.extend(obj["results"])
            if obj.get("next") is None:
                return results
            if not isinstance(obj["next"], str):
                raise PreviewError("Invalid pagination URL")
            next_url = obj["next"]
        raise PreviewError("NetBox pagination safety limit exceeded")


def nested(item: dict, key: str, field: str = "name"):
    value = item.get(key)
    return value.get(field) if isinstance(value, dict) else None


def compare(plan: dict, api: ReadOnlyNetBox, site_slug: str, role_slug: str) -> dict:
    if plan["summary"]["blocking_issue_codes"]:
        raise PreviewError("Fix offline data blockers before NetBox comparison")
    if not SLUG_RE.fullmatch(site_slug) or not SLUG_RE.fullmatch(role_slug):
        raise PreviewError("Invalid site/role slug")
    site_ok = sum(s.get("slug") == site_slug for s in api.list("/api/dcim/sites/", {"slug": site_slug})) == 1
    role_ok = sum(r.get("slug") == role_slug for r in api.list("/api/dcim/device-roles/", {"slug": role_slug})) == 1
    device_types = api.list("/api/dcim/device-types/", {"limit": 200})
    rows = []
    for device in plan["devices"]:
        types = [t for t in device_types if t.get("model") == device["model"]
                 and nested(t, "manufacturer") == device["manufacturer"]]
        hits = [d for d in api.list("/api/dcim/devices/", {"name": device["name"]})
                if d.get("name") == device["name"]]
        at_site = [d for d in hits if nested(d, "site", "slug") == site_slug]
        elsewhere = [d for d in hits if nested(d, "site", "slug") != site_slug]
        row = {"name": device["name"], "status": "needs_mapping", "missing_nics": None}
        if elsewhere or len(at_site) > 1:
            row["status"] = "ambiguous_name"
        elif not site_ok or not role_ok or len(types) != 1:
            row["status"] = "needs_mapping"
        elif not at_site:
            row["status"] = "missing_device"
        else:
            existing = at_site[0]
            if (nested(existing, "device_type", "id") != types[0].get("id")
                    or nested(existing, "role", "slug") != role_slug):
                row["status"] = "device_conflict"
            else:
                nic_names = {i.get("name") for i in api.list("/api/dcim/interfaces/", {"device_id": existing["id"]})}
                row["missing_nics"] = len(set(device["physical_interface_names"]) - nic_names)
                row["status"] = "existing_device"
        rows.append(row)
    return {"site_found": site_ok, "role_found": role_ok,
            "statuses": dict(Counter(r["status"] for r in rows)),
            "devices": rows, "http_methods": ["GET"], "writes": 0}


def save_private(path: Path, report: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".netbox-preview-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only NetBox DCIM preview; no writes")
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("output/netbox-preview.json"))
    parser.add_argument("--netbox-url", help="Optional HTTPS NetBox URL (read-only)")
    parser.add_argument("--site-slug", help="Existing NetBox site slug")
    parser.add_argument("--role-slug", help="Existing NetBox role slug")
    parser.add_argument("--ca-bundle", help="PEM trust bundle for corporate CA")
    args = parser.parse_args()
    try:
        plan = offline_plan(read_inventory(args.inventory))
        if args.netbox_url:
            if not args.site_slug or not args.role_slug:
                raise PreviewError("Online comparison needs --site-slug and --role-slug")
            token = os.environ.get("NETBOX_TOKEN", "").strip()
            if not token:
                raise PreviewError("Set NETBOX_TOKEN in the environment; do not put tokens in arguments")
            plan["netbox"] = compare(plan, ReadOnlyNetBox(args.netbox_url, token, args.ca_bundle),
                                      args.site_slug, args.role_slug)
        save_private(args.output, plan)
    except (PreviewError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    s = plan["summary"]
    print(f"READ-ONLY: devices={s['devices']} NICs={s.get('physical_interfaces', 0)} "
          f"MACs={s.get('current_macs', 0)} serials={s.get('serials_present', 0)} "
          f"deferred_interfaces={s.get('deferred_interfaces', 0)} "
          f"blockers={','.join(s['blocking_issue_codes']) or 'none'}")
    if "netbox" in plan:
        c = plan["netbox"]
        print(f"NETBOX GET-ONLY: site={c['site_found']} role={c['role_found']} statuses={c['statuses']}")
    print("Private preview saved:", args.output)
    return 2 if s["blocking_issue_codes"] else 0


if __name__ == "__main__":
    sys.exit(main())