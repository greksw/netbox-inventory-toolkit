# Inventory architecture and constraints

The **source of truth remains the hypervisor** during collection. The NetBox importer will be a separate program and PR.

```text
Corporate Proxmox VE cluster
  └─ local root / pvesh get (read-only)
       ├─ GET /nodes
       ├─ GET /nodes/{node}/status
       └─ GET /nodes/{node}/network
            └─ normalize → JSON (permissions 0600; output/ ignored by Git)
Optional: passwordless, verified-host-key SSH to read DMI sysfs and current hardware NIC MACs from peer nodes.
Later: review/dry-run → NetBox REST API synchronization.
```

## Decisions

1. Do not store cluster-specific addresses, credentials or serial numbers in this public repository. Report files are **sensitive** and must never be committed; `.gitignore` is a convenience, not an access-control boundary.
2. No NetBox write, no API token in the first release. Never guess device types, sites, primary IPs or physical port topology from a bridge name alone.
3. An unreachable node is an error in the saved report and yields exit code 2. Incomplete reports **must not** drive deletion or reconciliation.
4. DMI fields from sysfs include optional vendor, product, board descriptions and product serial. Asset tags are not collected. Missing or known-placeholder serial numbers are omitted.
5. `cpuinfo.cores` and `cpuinfo.cpus` are recorded as returned by Proxmox, not inferred. Values missing from PVE are null.
6. v0.3 reads the current MAC of hardware-backed (`/sys/class/net/*/device`) NICs; this is not necessarily the permanent factory MAC. Network entries are Linux configuration abstractions (physical, bridge, bond, VLAN). A Linux bridge is **not** automatically a physical switch or a NetBox cable. v0.3 checks local interface references, but its warnings are informational and do not validate physical cabling.
7. The scope of this project is corporate sites only; home/HA2 infrastructure is excluded.
8. The collector runs on one existing cluster member, requiring root for `pvesh`. For future off-host execution, prefer a separately scoped Proxmox API token over extending SSH privileges.
9. Future NetBox writes must use idempotent reconciliation with an explicit source ownership flag, reviewable dry-run and no default deletes.

## Exit codes

- `0` — all selected nodes collected and no warnings/errors.
- `2` — discovery failure or one or more node/DMI errors; JSON report may contain useful partial data.

## Data protection

The resulting JSON contains real hostnames, IPs, topology and potentially serial numbers and MACs; it must be treated as internal operational data. For GitHub examples use RFC 5737 documentation addresses (`192.0.2.0/24`, etc.), generic hostnames and fictitious DMI identifiers. Do not publish actual generated JSON, SSH keys, NetBox API tokens or configuration containing secrets.