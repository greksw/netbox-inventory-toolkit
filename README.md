# NetBox Inventory Toolkit

Read-only, staged discovery for **corporate** infrastructure, starting with Proxmox VE physical nodes. Source data is normalized for human review and for a **future** NetBox DCIM/IPAM importer. This repository is not an automatic NetBox synchronization service yet.

## v0.3: Proxmox VE physical-node inventory

The first collector retrieves:

- Node names and CPU model, sockets, cores and logical CPUs from the Proxmox API;
- Total installed RAM (bytes) from the Proxmox API;
- Network configuration entries (physical interfaces, Linux bridges, bonds, VLANs, IP/prefixes and basic relationships);
- Optional hardware vendor/model/motherboard and product serial using local DMI sysfs or verified-host-key SSH to cluster peers;
- MAC values from Proxmox when available or physical NIC sysfs; peer MACs require explicit `--mac-ssh`. Values are **current** interface MACs, not guaranteed factory-programmed addresses;
- Offline topology-reference audit for VLAN parent, bridge ports and bond slaves.
- No MAC is assigned to bridges or VLAN subinterfaces based on a physical NIC scan.

It does **not** collect VM/CT yet, does **not** write to NetBox and does **not** invent missing data. Real serial numbers and MACs are sensitive: never commit generated JSON.

### Requirements

- Proxmox VE with Python 3.9+ available (`python3 --version`). No Python dependencies outside the standard library.
- Run as **root on one corporate Proxmox VE cluster node**, because `pvesh` requires root.
- The node must be able to query `/nodes`, `/nodes/{node}/status`, and `/nodes/{node}/network` via `pvesh`.
- Optional DMI from *other* nodes requires preconfigured key-based SSH access with already verified host keys (`StrictHostKeyChecking=yes`). No password prompts.

### Run (first do one node)

```bash
# On a corporate Proxmox node (after cloning the repository):
cd netbox-inventory-toolkit
python3 collectors/proxmox_inventory.py --node "$(hostname -s)" --cluster-label corp-pve

# Inspect locally (private data):
python3 -m json.tool output/proxmox-inventory.json | less
```

Then query every cluster member **without using SSH** (only local node has DMI):

```bash
python3 collectors/proxmox_inventory.py --cluster-label corp-pve \
  --output output/proxmox-inventory.json
```

When remote nodes are accessible through SSH keys:

```bash
python3 collectors/proxmox_inventory.py --cluster-label corp-pve \
  --dmi-ssh --ssh-user root --output output/proxmox-inventory.json
```

This does not modify Proxmox or NetBox. Output is atomic, written with file permissions `0600`; `output/` is ignored by Git. Avoid running commands inside a publicly accessible directory or sending real inventory JSON to public issues or PRs.

### Quick, sanitized summary for troubleshooting

```bash
python3 - <<'PY'
import json
from collections import Counter
with open('output/proxmox-inventory.json', encoding='utf-8') as f:
    data = json.load(f)
print('Summary:', data['summary'])
for n in data['nodes']:
    print(n['name'], 'CPU:', n['cpu'], 'RAM GiB:',
          round((n['memory_total_bytes'] or 0) / 2**30, 1),
          'Interfaces by type:', dict(Counter(i.get('type', 'unknown') for i in n['network_interfaces'])),
          'DMI:', n.get('dmi', {}).get('model', 'not collected')))
print('Error stages:', dict(Counter(e['stage'] for e in data['errors'])))
PY
```

**Before posting output, anonymize node names and vendor/model if required by corporate policy.** Never share the full JSON publicly.

### v0.3 validation (safe counts only)

After an authorized DMI collection, run:

```bash
python3 collectors/proxmox_inventory.py --dmi-ssh --mac-ssh --cluster-label corp-pve \
  --output output/proxmox-inventory-v03.json

python3 - <<'PY'
import json
with open('output/proxmox-inventory-v03.json', encoding='utf-8') as f:
    report = json.load(f)
print('Collection:', report['summary'])
print('Audit:', report['audit_summary'])
for node in report['nodes']:
    a = node['network_audit']
    print(node['name'], 'DMI:', bool(node.get('dmi')),
          'serial-present:', bool(node.get('dmi', {}).get('serial_number')),
          'MAC-count:', a['mac_count'], 'topology-issues:', len(a['topology_issues']))
    if a['topology_issues']:
        from collections import Counter
        print('  issue-codes:', dict(Counter(x['code'] for x in a['topology_issues'])))
PY
```

`--mac-ssh` uses strict host-key checking and BatchMode, without password prompts. It reads `/sys/class/net/*/{device,address}` on peers and never changes network state. This can recover current MACs when `pvesh` omits them. Run `--dmi-ssh` without `--mac-ssh` to avoid remote MAC queries.

Do **not** print serial values or raw JSON in public chats. The audit only checks
names of interfaces within each node, not rack cabling, VLAN reachability,
storage uplinks or NetBox model readiness. Some API responses lack MAC values;
absence is reported as missing, not a collection error.

### Testing without Proxmox

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q collectors tests
```

The tests use synthetic PVE responses and do not need a running cluster. Output shape: [`examples/inventory.example.json`](examples/inventory.example.json). Design and security constraints: [`docs/architecture.md`](docs/architecture.md).

## Next milestones

1. Validate v0.3 on the nine corporate Proxmox nodes, record serial/MAC coverage and topology issue codes.
2. Add QEMU/LXC inventory (VMIDs, node membership and vNIC metadata) in a separate PR.
3. Add a human-reviewed NetBox data model (Sites, Device Types, Devices, Clusters, VMs, Interfaces, VLANs and Prefixes).
4. Implement `check`, `dry-run`, `apply` for an **idempotent** NetBox API importer; read-only is the default.
5. Expand discovery to corporate MikroTik and Linux/Windows sources.

## References

- [Official Proxmox VE pvesh documentation](https://pve.proxmox.com/pve-docs/pvesh.1.html)
- [Proxmox VE API viewer](https://pve.proxmox.com/pve-docs/api-viewer/)
- [NetBox REST API documentation](https://netbox.readthedocs.io/en/stable/integrations/rest-api/)

## Licence

No open-source license has been chosen yet. Until one is added, normal copyright restrictions apply.
## Read-only NetBox DCIM preview

After collecting and verifying the complete Proxmox inventory with schema v0.3, run:

```bash
python3 netbox/preview.py \
  --inventory output/proxmox-inventory-v03.json \
  --output output/netbox-preview.json
```

The output summarizes candidate physical devices and NICs without modifying NetBox. Non-physical interfaces and IP assignments are deferred. Optional *read-only* NetBox API comparison requires an existing Site and Device Role and is documented in [docs/netbox-preview.md](docs/netbox-preview.md). The comparator intentionally has no apply mode and does not print raw serials, MACs or IPs.
## Enrich existing NetBox hardware

The offline collector and read-only preview are separate from the
optional guarded enrichment module. The default is a dry-run; an explicit
apply confirmation is required to update only existing device serials and
physical NIC primary MACs. See [docs/hardware-enrichment.md](docs/hardware-enrichment.md).

## Daily drift detection (read-only)

`netbox/drift_audit.py` gathers a fresh cluster snapshot and compares existing
NetBox devices, interfaces, hardware serials and physical NIC MACs via GET-only
HTTPS. It exits 0 when clean, 1 for drift and 2 on query/collection errors.
See [docs/daily-drift-audit.md](docs/daily-drift-audit.md) for configuration,
read-only token permissions, CA trust and systemd timer deployment. No
automatic NetBox writes are enabled.
