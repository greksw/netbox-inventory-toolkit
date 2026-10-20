#!/usr/bin/env python3
"""Strict read-only HTTPS collectors for RouterOS REST and NetBox 4.x IPAM.

GET only, restricted endpoints, HTTPS certificate validation, no redirects,
no environment proxies, and no raw identifiers in error messages.
No device configuration changes are possible through this module.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import re
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlsplit
from urllib.request import (
    Request, HTTPSHandler, HTTPRedirectHandler, ProxyHandler, build_opener,
)

from routeros.ipam_audit import (
    IPAMAuditError, checked_address, checked_name, checked_prefix, checked_vid,
)

NETBOX_ENDPOINTS = frozenset({
    "/api/dcim/devices/",
    "/api/dcim/interfaces/",
    "/api/ipam/vlans/",
    "/api/ipam/prefixes/",
    "/api/ipam/ip-addresses/",
})
ROUTER_ENDPOINTS = frozenset({
    "/rest/interface/vlan",
    "/rest/ip/address",
})
SAFE_DEVICE = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
SAFE_SLUG = re.compile(r"^[a-z0-9_-]{1,100}$")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise IPAMAuditError("Unexpected HTTPS redirect")


def safe_origin(url: str) -> str:
    if not isinstance(url, str):
        raise IPAMAuditError("HTTPS base URL is required")
    parts = urlsplit(url)
    try:
        port = parts.port
    except ValueError:
        raise IPAMAuditError("Invalid HTTPS port") from None
    if (parts.scheme != "https" or not parts.hostname or
            parts.username is not None or parts.password is not None or
            parts.query or parts.fragment or parts.path not in ("", "/") or
            port == 0):
        raise IPAMAuditError("Expected https://hostname[:port] without path")
    return "https://" + parts.netloc


def https_client(ca_file: str | None = None):
    try:
        context = ssl.create_default_context(cafile=ca_file)
    except (ValueError, OSError):
        raise IPAMAuditError("Invalid trusted CA bundle") from None
    return build_opener(
        ProxyHandler({}), HTTPSHandler(context=context), NoRedirect())


def fetch_json(opener, origin: str, endpoint: str, auth: str,
               params: dict | None = None):
    target = origin + endpoint + ("?" + urlencode(params) if params else "")
    request = Request(target, method="GET", headers={
        "Authorization": auth,
        "Accept": "application/json",
    })
    try:
        with opener.open(request, timeout=12) as response:
            if response.status != 200:
                raise IPAMAuditError("Unexpected HTTPS status")
            raw = response.read(4_000_001)
    except (HTTPError, URLError, OSError, ValueError):
        raise IPAMAuditError("HTTPS GET failed") from None
    if len(raw) > 4_000_000:
        raise IPAMAuditError("Oversized HTTPS response")
    try:
        return json.loads(raw)
    except (ValueError, UnicodeError):
        raise IPAMAuditError("Malformed HTTPS JSON") from None


class RouterOSReader:
    def __init__(self, origin: str, username: str, password: str,
                 ca_file: str | None = None):
        self.origin = safe_origin(origin)
        if (not isinstance(username, str) or not username or
                any(ch in username for ch in "\r\n:") or
                not isinstance(password, str) or not password):
            raise IPAMAuditError("Missing or invalid RouterOS credentials")
        credentials = base64.b64encode(
            (username + ":" + password).encode("utf-8")).decode("ascii")
        self.auth = "Basic " + credentials
        self.opener = https_client(ca_file)

    def listing(self, endpoint: str):
        if endpoint not in ROUTER_ENDPOINTS:
            raise IPAMAuditError("Unapproved RouterOS API path")
        data = fetch_json(self.opener, self.origin, endpoint, self.auth)
        if not isinstance(data, list):
            raise IPAMAuditError("RouterOS list response required")
        if len(data) > 50000:
            raise IPAMAuditError("RouterOS result safety limit")
        return data


class NetBoxReader:
    def __init__(self, origin: str, token: str, ca_file: str | None = None):
        self.origin = safe_origin(origin)
        if not isinstance(token, str) or not re.fullmatch(
                r"nbt_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token):
            raise IPAMAuditError("NetBox v2 API token is required")
        self.auth = "Bearer " + token
        self.opener = https_client(ca_file)

    def listing(self, endpoint: str, params: dict | None = None):
        if endpoint not in NETBOX_ENDPOINTS:
            raise IPAMAuditError("Unapproved NetBox API path")
        query = dict(params or {})
        query.setdefault("limit", 200)
        current = self.origin + endpoint + "?" + urlencode(query)
        seen = set()
        results = []
        for _ in range(100):
            if current in seen:
                raise IPAMAuditError("Pagination cycle")
            seen.add(current)
            parts = urlsplit(current)
            if (parts.scheme != "https" or
                    "https://" + parts.netloc != self.origin or
                    parts.path != endpoint or parts.fragment or
                    parts.username or parts.password):
                raise IPAMAuditError("Unsafe NetBox pagination")
            # Fetch the exact vetted URL, not a server-influenced arbitrary endpoint.
            data = fetch_json(self.opener, self.origin, endpoint, self.auth,
                              dict([(k, v[0]) for k, v in
                                    __import__("urllib.parse", fromlist=["parse_qs"])
                                    .parse_qs(parts.query).items()]))
            if not isinstance(data, dict) or not isinstance(data.get("results"), list):
                raise IPAMAuditError("Malformed NetBox paginated response")
            results.extend(data["results"])
            if len(results) > 50000:
                raise IPAMAuditError("NetBox result safety limit")
            nxt = data.get("next")
            if nxt is None:
                if type(data.get("count")) is not int or data["count"] != len(results):
                    raise IPAMAuditError("Incomplete NetBox listing")
                return results
            if not isinstance(nxt, str):
                raise IPAMAuditError("Invalid NetBox pagination link")
            current = urljoin(self.origin + "/", nxt)
        raise IPAMAuditError("NetBox pagination page limit")


def router_bool(value: object, field: str) -> bool:
    if value is True or value == "true":
        return True
    if value is False or value == "false":
        return False
    raise IPAMAuditError("Invalid RouterOS boolean " + field)


def routeros_snapshot(reader) -> dict:
    vlans = []
    for item in reader.listing("/rest/interface/vlan"):
        if not isinstance(item, dict):
            raise IPAMAuditError("Malformed RouterOS VLAN record")
        try:
            vid = checked_vid(int(item["vlan-id"]))
            name = checked_name(item["name"])
            parent = checked_name(item["interface"])
        except (KeyError, ValueError, TypeError, OverflowError):
            raise IPAMAuditError("Incomplete RouterOS VLAN record") from None
        vlans.append({
            "vid": vid, "name": name, "parent": parent,
            "disabled": router_bool(item.get("disabled", "false"), "disabled"),
        })
    addresses = []
    for item in reader.listing("/rest/ip/address"):
        if not isinstance(item, dict):
            raise IPAMAuditError("Malformed RouterOS IP record")
        try:
            address = checked_address(item["address"])
            interface = checked_name(item["interface"])
        except KeyError:
            raise IPAMAuditError("Incomplete RouterOS IP record") from None
        addresses.append({
            "address": address, "interface": interface,
            "dynamic": router_bool(item.get("dynamic", "false"), "dynamic"),
            "disabled": router_bool(item.get("disabled", "false"), "disabled"),
        })
    return {"schema_version": "routeros-ipam-0.1",
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "vlans": vlans, "addresses": addresses}


def nested_id(value):
    if type(value) is int:
        return value
    if isinstance(value, dict) and type(value.get("id")) is int:
        return value["id"]
    return None


def nested_slug(value):
    return value.get("slug") if isinstance(value, dict) else None


def netbox_snapshot(reader, *, router_name: str, site_slug: str,
                    vlan_group_slug: str):
    if (not SAFE_DEVICE.fullmatch(router_name) or
            not SAFE_SLUG.fullmatch(site_slug) or
            not SAFE_SLUG.fullmatch(vlan_group_slug)):
        raise IPAMAuditError("Invalid router, site or VLAN group selector")
    devices = [
        rec for rec in reader.listing("/api/dcim/devices/", {"name": router_name})
        if isinstance(rec, dict) and rec.get("name") == router_name
    ]
    if len(devices) != 1:
        raise IPAMAuditError("NetBox router not unique or missing")
    device = devices[0]
    if (nested_slug(device.get("site")) != site_slug or
            nested_slug(device.get("role")) != "router"):
        raise IPAMAuditError("Unexpected router site or role")
    device_id = device.get("id")
    if type(device_id) is not int:
        raise IPAMAuditError("Router PK missing")
    interfaces = {}
    for rec in reader.listing("/api/dcim/interfaces/",
                              {"device_id": device_id}):
        if not isinstance(rec, dict) or nested_id(rec.get("device")) != device_id:
            raise IPAMAuditError("Unexpected NetBox router interface owner")
        iid = rec.get("id")
        name = checked_name(rec.get("name"))
        if type(iid) is not int or iid in interfaces or name in interfaces.values():
            raise IPAMAuditError("Duplicate or invalid router interface")
        interfaces[iid] = name
    if not interfaces:
        raise IPAMAuditError("Router has no interfaces")
    vlans = {}
    for rec in reader.listing("/api/ipam/vlans/"):
        if not isinstance(rec, dict):
            raise IPAMAuditError("Malformed NetBox VLAN")
        if nested_slug(rec.get("group")) != vlan_group_slug:
            continue
        vid = checked_vid(rec.get("vid"))
        pk = rec.get("id")
        if type(pk) is not int or pk in vlans:
            raise IPAMAuditError("Duplicate VLAN ID record")
        vlans[pk] = vid
    if not vlans or len(vlans) != len(set(vlans.values())):
        raise IPAMAuditError("VLAN group missing or duplicate VIDs")
    assigned_prefix = {}
    for rec in reader.listing("/api/ipam/prefixes/"):
        if not isinstance(rec, dict):
            raise IPAMAuditError("Malformed NetBox prefix record")
        pk = nested_id(rec.get("vlan"))
        if pk not in vlans:
            continue
        prefix = checked_prefix(rec.get("prefix"))
        if pk in assigned_prefix:
            raise IPAMAuditError("Multiple prefixes in selected VLAN")
        assigned_prefix[pk] = prefix
    if len(assigned_prefix) != len(vlans):
        raise IPAMAuditError("Incomplete VLAN prefix assignments")
    addresses = []
    for rec in reader.listing("/api/ipam/ip-addresses/"):
        if not isinstance(rec, dict):
            raise IPAMAuditError("Malformed NetBox IP record")
        if rec.get("assigned_object_type") != "dcim.interface":
            continue
        iid = rec.get("assigned_object_id")
        obj_id = nested_id(rec.get("assigned_object"))
        if iid is not None and obj_id is not None and iid != obj_id:
            raise IPAMAuditError("Conflicting IP assignment identifiers")
        iid = iid if type(iid) is int else obj_id
        if iid not in interfaces:
            continue
        addresses.append({
            "address": checked_address(rec.get("address")),
            "interface": interfaces[iid],
        })
    return {
        "schema_version": "netbox-router-ipam-0.1",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "vlans": [{"vid": vlans[i], "prefix": assigned_prefix[i]}
                  for i in sorted(vlans, key=lambda item: vlans[item])],
        "addresses": addresses,
    }
