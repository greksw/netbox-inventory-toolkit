# Read-only live RouterOS ↔ NetBox IPAM audit and Prometheus

This optional deployment is **not an installer**. Nothing writes to RouterOS
or NetBox. Use only reviewed local settings; do not publish real hosts, IPs,
tokens, VPN details, MACs, serials, or raw snapshots.

## Inputs and trust boundary

- Python 3.11+, working SSH client, trusted NetBox TLS CA, local systemd and
  Node Exporter textfile collector.
- Dedicated RouterOS `ssh,read` user, source-IP restricted; verified SSH
  host key and root-private SSH identity. Two hard-coded read-only SSH JSON
  commands are supported; do not enable RouterOS HTTP to run this collector.
- Dedicated NetBox API v2 Bearer token with **write disabled**, restricted to
  view Device, Interface, VLAN, Prefix and IPAddress. Store in a root-owned
  mode 0600 file, rotate on expiry; never place tokens in Git.
- Explicit NetBox router, site, VLAN-group identifiers; approved counts.
- The exact pair `address + interface` in `approved_dynamic` may be
  approved **after manual IPsec provenance review only**. The collector does
  not automatically verify IPsec policy/NAT/peer identity at runtime.

Copy `examples/routeros-ipam.json.example` into a protected *local* config.
Its documentation-only `192.0.2.1` and `*.invalid` values **must** be
replaced. The default path is `/etc/netbox-inventory/routeros-ipam.json`.
Example installation:

```bash
install -d -o root -g root -m 0700 /etc/netbox-inventory/ssh
install -o root -g root -m 0600 examples/routeros-ipam.json.example \
    /etc/netbox-inventory/routeros-ipam.json
# Edit private settings and provision token, verified known_hosts, key and CA.
cd /opt/netbox-inventory-toolkit
python3.11 -m routeros.run_local_audit
echo "Audit exit code: $?"
```

The live runner performs two allowlisted RouterOS SSH reads and HTTPS GET
requests to NetBox. It compares VLAN IDs and prefixes and exact static
IPv4/interface pairs; invalid snapshots or approved count mismatches fail
closed. Its output is limited to aggregate counts and categorical drift:

- `0 CLEAN`: complete evidence, no unexpected differences.
- `1 DRIFT`: differences from reviewed static VLAN/IP baseline or unapproved
  dynamic entries.
- `2 ERROR`: incomplete evidence, invalid local config or failed source.

## Prometheus textfile exporter

```bash
python3.11 -m routeros.textfile_export \
  --output-dir /var/lib/node_exporter/textfile_collector
restorecon -v /var/lib/node_exporter/textfile_collector/netbox-routeros-ipam.prom
curl -fsS http://127.0.0.1:9100/metrics | grep '^netbox_routeros_ipam_audit_'
```

The exporter atomically replaces **only**
`netbox-routeros-ipam.prom`. Its numeric-only output is mode 0644 so a
separate unprivileged `node_exporter` process can read it; private
credentials remain 0600. `netbox_routeros_ipam_audit_status` is 0/1/2;
`_differences` and count metrics are intentionally **absent on ERROR**.
`_timestamp_seconds` is the time of the last publication **attempt**, not a
guarantee of a successful audit. Monitor the age of that metric and its
absence too.

## systemd

Review paths and host scheduling timezone before copying templates:

```bash
install -o root -g root -m 0644 deploy/netbox-routeros-ipam.service /etc/systemd/system/
install -o root -g root -m 0644 deploy/netbox-routeros-ipam.timer /etc/systemd/system/
systemd-analyze verify /etc/systemd/system/netbox-routeros-ipam.service
systemctl daemon-reload
systemctl start netbox-routeros-ipam.service
systemctl show netbox-routeros-ipam.service -p Result -p ExecMainStatus
# Enable only after a successful manual smoke test:
systemctl enable --now netbox-routeros-ipam.timer
systemctl list-timers --all netbox-routeros-ipam.timer
```

`SuccessExitStatus=1` makes a DRIFT result an expected systemd invocation
outcome (status still 1 in Prometheus), while an ERROR result (2) fails the
unit. Timer schedule uses the server's local timezone at 06:45 plus up to
five minutes random delay, and `Persistent=true` for missed runs.

## Alerts and notifications

Configure these four rules in your existing Prometheus alert rule file,
using the exact `instance` and `job` labels from `/api/v1/targets`:

| Name | Expression | Severity |
| --- | --- | --- |
| RouterOSIPAMDrift | `netbox_routeros_ipam_audit_status == 1` | warning |
| RouterOSIPAMAuditError | `netbox_routeros_ipam_audit_status == 2` | critical |
| RouterOSIPAMAuditStale | `time() - netbox_routeros_ipam_audit_timestamp_seconds > 93600` | warning |
| RouterOSIPAMAuditMissing | `absent(netbox_routeros_ipam_audit_status{job="node",instance="YOUR_NODE_INSTANCE"})` | critical |

Use `promtool check rules` before reloading Prometheus and check
`/api/v1/rules?type=alert` after a rule evaluation interval.
`amtool config routes test` checks routing without delivering actual
notifications. A live delivery test requires explicit operational approval.
Historical successful email/webhook counters do **not** prove delivery of
one specific new alert.

## Limitations

The current scope does not include IPv6, VRF-aware prefixes, overlapping
routing domains, bridge VLAN tables or automated validation of dynamic IKEv2
Mode Config provenance. A reviewed dynamic exception is not evidence of an
active VPN peer. Do not blanket-exclude all dynamic IP addresses.
Run `python3 -m unittest discover -s tests -v` before rollout. Unit tests
use synthetic data; run a private site-specific smoke test after deployment.
