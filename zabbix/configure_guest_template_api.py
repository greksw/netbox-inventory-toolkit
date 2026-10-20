#!/usr/bin/env python3
"""Idempotent Zabbix 7.0 guest-drift template setup; preview by default.

Uses existing ZabbixAPI helper; never changes actions or existing item definitions.
"""
import argparse
import getpass
import sys
from configure_template_api import ZabbixAPI

TEMPLATE = "Template NetBox Guest Inventory Drift"
VISIBLE = "NetBox Guest Inventory Drift"
KEYS = ("netbox.guest.audit.status", "netbox.guest.audit.differences", "netbox.guest.audit.timestamp")
NAMES = ("NetBox guest audit status (0=clean,1=drift,2=error)",
         "NetBox guest audit differences", "NetBox guest audit timestamp")
def find_exact(records, field, value):
    matches = [r for r in records if r.get(field) == value]
    if len(matches) > 1:
        raise RuntimeError("Ambiguous Zabbix object")
    return matches[0] if matches else None


def execute(api, host_name, apply=False):
    hosts = api.call("host.get", {"output": ["hostid", "host", "name"], "filter": {"host": [host_name]},
                                   "selectParentTemplates": ["templateid", "host"]})
    host = find_exact(hosts, "host", host_name)
    if host is None:
        raise RuntimeError("Host not found")
    templates = api.call("template.get", {"output": ["templateid", "host", "name"],
                                            "filter": {"host": [TEMPLATE]}})
    template = find_exact(templates, "host", TEMPLATE)
    if template is None:
        groups = api.call("templategroup.get", {"output": ["groupid", "name"], "filter": {"name": ["Templates"]}})
        if not groups:
            raise RuntimeError("Template group Templates not found; configure it first")
        group = find_exact(groups, "name", "Templates")
        print("CREATE template in group:", group["name"])
        if apply:
            tid = api.call("template.create", {"host": TEMPLATE, "name": VISIBLE,
                     "groups": [{"groupid": group["groupid"]}]})["templateids"][0]
            template = {"templateid": tid, "host": TEMPLATE, "name": VISIBLE}
    if template is None:
        print("DRY-RUN: template, 3 items, 4 triggers and host link would be checked/created")
        return
    tid = template["templateid"]
    items = api.call("item.get", {"templateids": [tid],
         "output": ["itemid", "key_", "type", "value_type", "delay", "status"]})
    for key, name in zip(KEYS, NAMES):
        matches = [x for x in items if x["key_"] == key]
        if len(matches) > 1:
            raise RuntimeError("Duplicate item key: " + key)
        if matches:
            x = matches[0]
            if any(str(x[f]) != value for f, value in
                    (("type", "0"), ("value_type", "3"), ("status", "0"))):
                raise RuntimeError("Conflicting item configuration: " + key)
            print("EXISTS item:", key)
        else:
            print("CREATE item:", key)
            if apply:
                api.call("item.create", {"name": name, "key_": key,
                          "hostid": tid, "type": 0, "value_type": 3, "delay": "5m"})
    expressions = [
      ("NetBox guest: Inventory drift detected", f"last(/{TEMPLATE}/{KEYS[0]})=1", 2),
      ("NetBox guest: Inventory audit failed", f"last(/{TEMPLATE}/{KEYS[0]})=2", 4),
      ("NetBox guest: Inventory audit is stale (>26h)", f"now()-last(/{TEMPLATE}/{KEYS[2]})>93600", 3),
      ("NetBox guest: No audit monitoring data received", f"nodata(/{TEMPLATE}/{KEYS[0]},15m)=1", 3),
    ]
    existing = api.call("trigger.get", {"templateids": [tid], "expandExpression": True,
                 "output": ["triggerid", "description", "expression", "priority", "status"]})
    for name, expression, priority in expressions:
        matching = [t for t in existing if t["description"] == name]
        if len(matching) > 1:
            raise RuntimeError("Duplicate trigger: " + name)
        if matching:
            t = matching[0]
            if (t["expression"] != expression or str(t["priority"]) != str(priority)
                    or str(t["status"]) != "0"):
                raise RuntimeError("Conflicting trigger: " + name)
            print("EXISTS trigger:", name)
        else:
            print("CREATE trigger:", name)
            if apply:
                api.call("trigger.create", {"description": name, "expression": expression,
                         "priority": priority,
                         "tags": [{"tag": "component", "value": "netbox-guest-drift"}]})
    parent_ids = {x["templateid"] for x in host.get("parentTemplates", [])}
    if tid not in parent_ids:
        print("LINK host:", host_name)
        if apply:
            api.call("host.massadd", {"hosts": [{"hostid": host["hostid"]}],
                     "templates": [{"templateid": tid}]})
    else:
        print("EXISTS host link:", host_name)
    print("DONE:", "APPLY" if apply else "DRY-RUN")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--url", required=True)
    p.add_argument("--host", required=True)
    p.add_argument("--login", action="store_true")
    p.add_argument("--apply", action="store_true")
    args = p.parse_args()
    try:
        api = ZabbixAPI(args.url)
        print("API:", api.call("apiinfo.version"))
        if args.login:
            username = input("Zabbix username: ").strip()
            password = getpass.getpass("Zabbix password: ")
            api.token = api.call("user.login", {"username": username, "password": password})
        else:
            api.token = getpass.getpass("Zabbix API token (hidden): ").strip()
        execute(api, args.host, args.apply)
        return 0
    except (RuntimeError, ValueError, OSError) as exc:
        print("ERROR:", str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
