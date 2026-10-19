#!/usr/bin/env python3
"""Idempotent Zabbix 7.0 template trigger setup, using only the JSON-RPC API.

Default is read-only preview. --apply creates *missing* triggers. Existing
triggers with matching descriptions but different expressions are never edited.
API secret or login password is requested interactively and never persisted.
"""
import argparse
import getpass
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

KEYS = (
    "netbox.audit.status",
    "netbox.audit.differences",
    "netbox.audit.timestamp",
)


def trigger_definitions(template_host):
    ref = lambda key: f"/{template_host}/{key}"
    return [
        ("NetBox: Inventory drift detected", f"last({ref(KEYS[0])})=1", 2),
        ("NetBox: Inventory audit failed", f"last({ref(KEYS[0])})=2", 4),
        ("NetBox: Inventory audit is stale (>26h)",
         f"now()-last({ref(KEYS[2])})>93600", 3),
        ("NetBox: No audit monitoring data received",
         f"nodata({ref(KEYS[0])},15m)=1", 3),
    ]


class ZabbixAPI:
    def __init__(self, url, timeout=15):
        parts = urlsplit(url)
        if (parts.scheme not in ("http", "https") or not parts.netloc or
                not parts.path.endswith("/api_jsonrpc.php") or
                parts.username or parts.password or parts.query or parts.fragment or
                (parts.scheme == "http" and parts.hostname not in ("127.0.0.1", "localhost", "::1"))):
            raise ValueError("Use HTTPS API URL or http://127.0.0.1/.../api_jsonrpc.php")
        self.url = url
        self.timeout = timeout
        self.token = None
        self.seq = 0

    def call(self, method, params=None):
        self.seq += 1
        body = json.dumps({"jsonrpc": "2.0", "method": method,
                           "params": {} if params is None else params,
                           "id": self.seq}).encode()
        headers = {"Content-Type": "application/json-rpc", "Accept": "application/json"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        request = Request(self.url, data=body, headers=headers, method="POST")
        try:
            with urlopen(request, timeout=self.timeout) as stream:
                answer = json.load(stream)
        except HTTPError as exc:
            raise RuntimeError(f"Zabbix API HTTP status {exc.code}") from None
        except (URLError, ValueError, TimeoutError):
            raise RuntimeError("Zabbix API unavailable or returned invalid JSON") from None
        if not isinstance(answer, dict):
            raise RuntimeError("Invalid Zabbix API response")
        if "error" in answer:
            error = answer["error"]
            raise RuntimeError(f"API {method}: {error.get('message', 'error')}: "
                               f"{error.get('data', 'unknown reason')}")
        if "result" not in answer:
            raise RuntimeError("Missing Zabbix API result")
        return answer["result"]


def find_template(api, exact_name):
    records = {}
    for field in ("host", "name"):
        for record in api.call("template.get", {
            "output": ["templateid", "host", "name"],
            "filter": {field: exact_name}
        }):
            if record.get(field) == exact_name:
                records[record["templateid"]] = record
    if len(records) != 1:
        raise RuntimeError(f"Expected exactly one template matching {exact_name!r}; "
                           f"found {len(records)}. Specify its exact technical or visible name")
    return next(iter(records.values()))


def plan(api, name):
    template = find_template(api, name)
    tid = template["templateid"]
    items = api.call("item.get", {"templateids": [tid],
                                   "output": ["itemid", "key_", "type", "value_type", "status"],
                                   "filter": {"key_": list(KEYS)}})
    unique_items = {i["key_"]: i for i in items if i["key_"] in KEYS}
    if len(items) != len(KEYS) or set(unique_items) != set(KEYS):
        raise RuntimeError("Template must already have exactly three NetBox audit items")
    for key, item in unique_items.items():
        if str(item["type"]) != "0" or str(item["value_type"]) != "3" or str(item["status"]) != "0":
            raise RuntimeError(f"Item {key} must be enabled, Zabbix agent (passive), Numeric unsigned")
    existing = api.call("trigger.get", {
        "expandExpression": True,
        "templateids": [tid],
        "output": ["triggerid", "description", "expression", "priority", "status"]
    })
    descriptions = {}
    for t in existing:
        descriptions.setdefault(t["description"], []).append(t)
    result = []
    for title, expression, severity in trigger_definitions(template["host"]):
        matches = descriptions.get(title, [])
        if len(matches) > 1:
            raise RuntimeError(f"Duplicate existing triggers: {title}")
        if matches:
            t = matches[0]
            if t["expression"] != expression or str(t["priority"]) != str(severity) or str(t["status"]) != "0":
                raise RuntimeError(f"Existing trigger conflicts with requested definition: {title}")
        result.append((title, expression, severity, bool(matches)))
    return template, result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--url", required=True,
                   help="Zabbix frontend API URL; local HTTP allowed on loopback only")
    p.add_argument("--template", default="NetBox Inventory Drift",
                   help="Exact template visible or technical name")
    p.add_argument("--apply", action="store_true", help="Create missing triggers (default dry-run)")
    p.add_argument("--login", action="store_true", help="Prompt for Zabbix username/password rather than API token")
    args = p.parse_args()
    try:
        api = ZabbixAPI(args.url)
        print("Zabbix API version:", api.call("apiinfo.version"))
        if args.login:
            username = input("Zabbix username: ").strip()
            password = getpass.getpass("Zabbix password: ")
            api.token = api.call("user.login", {"username": username, "password": password})
            password = None
        else:
            api.token = getpass.getpass("Zabbix API token (hidden): ").strip()
            if not api.token:
                raise RuntimeError("Empty API token")
        template, triggers = plan(api, args.template)
        print("Template technical name:", template["host"])
        print("Template visible name:  ", template["name"])
        print("Template ID:            ", template["templateid"])
        print("Items: 3 validated (passive, unsigned, enabled)")
        for title, expression, severity, exists in triggers:
            print(("EXISTS" if exists else "CREATE"), f"severity={severity}", title)
            print("   ", expression)
        missing = [t for t in triggers if not t[3]]
        if not args.apply:
            print(f"DRY-RUN: {len(missing)} trigger(s) would be created. No changes made.")
            return 0
        for title, expression, severity, exists in triggers:
            if exists:
                continue
            result = api.call("trigger.create", {
                "description": title, "expression": expression, "priority": severity,
                "tags": [{"tag": "component", "value": "netbox-drift"}],
            })
            print("CREATED", title, result.get("triggerids", []))
        _, verified = plan(api, args.template)
        if not all(row[3] for row in verified):
            raise RuntimeError("Verification failed: some triggers are still missing")
        print("SUCCESS: 4/4 triggers present; original template items unchanged")
        return 0
    except (RuntimeError, ValueError, OSError) as exc:
        print("ERROR:", str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
