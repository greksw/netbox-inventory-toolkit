# NetBox Inventory Toolkit

Read-only, staged discovery for **corporate** infrastructure, starting with Proxmox VE physical nodes. Source data is normalized for human review and for a **future** NetBox DCIM/IPAM importer. This repository is not an automatic NetBox synchronization service yet.

## v0.1: Proxmox VE physical-node inventory

The first collector retrieves:

- Node names and CPU model, sockets, cores and logical CPUs from the Proxmox API;
- Total installed RAM (bytes) from the Proxmox API;
- Network configuration entries (physical interfaces, Linux bridges, bonds, VLANs, IP/prefixes and basic relationships);
- Optional hardware vendor/model/motherboard using local DMI sysfs, or optional SSH to peer nodes.

It does **not** collect VM/CT yet, does **not** write to NetBox, does **not** invent missing data and does **not** read serial numbers.

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

### Testing without Proxmox

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q collectors tests
```

The tests use synthetic PVE responses and do not need a running cluster. Output shape: [`examples/inventory.example.json`](examples/inventory.example.json). Design and security constraints: [`docs/architecture.md`](docs/architecture.md).

## Next milestones

1. Validate this collector against the nine corporate Proxmox nodes, record field differences and expected interfaces.
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