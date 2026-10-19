# NetBox DCIM preview: read-only planning and comparison

This is a deliberately conservative stage between corporate Proxmox inventory collection and eventual NetBox import. There is no POST, PUT, PATCH or DELETE in this tool. It does not create a NetBox Device or Interface.

## 1. Offline preview

On the corporate Proxmox collector host, with an existing v0.3 inventory:

```bash
cd /root/netbox-inventory-toolkit
python3 netbox/preview.py \
  --inventory output/proxmox-inventory-v03.json \
  --output output/netbox-preview.json
```

The console displays aggregate counts and blocking issue codes. The saved JSON is owner-readable only (0600). It contains hostnames, manufacturer/model, interface **names** and presence/coverage counts. It does **not** copy raw MAC values, serial values or IP addresses.

The plan fails closed for incomplete collection, errors, inconsistent topology, duplicates, or missing DMI manufacturer/model. The plan includes only physical Ethernet interfaces as a candidate first pass; 342 Proxmox bridge/VLAN interface entries and their IP assignments are deliberately deferred for mapping decisions.

## 2. Optional read-only NetBox comparison

NetBox needs a designated corporate Site and Device Role, plus deliberately mapped Manufacturer and Device Type values. Do not invent these from hostnames.

Create a dedicated **read-only NetBox API token v2** (prefix `nbt_`) with the minimum necessary view permissions. Use the CA certificate publicly exported from your corporate PKI, **not the CA private key**. The following command contains **example-only** names and paths:

```bash
export NETBOX_TOKEN='nbt_EXAMPLE.REPLACE_WITH_REAL_SECRET'
python3 netbox/preview.py \
  --inventory output/proxmox-inventory-v03.json \
  --netbox-url 'https://netbox.corp.example' \
  --site-slug 'office' --role-slug 'hypervisor' \
  --ca-bundle /etc/pki/ca-trust/source/anchors/corporate-root-ca.pem \
  --output output/netbox-preview.json
unset NETBOX_TOKEN
```

Prefer an environment variable set without saving token values in shell history. For example, use `read -rs NETBOX_TOKEN; export NETBOX_TOKEN` then paste the token at the hidden prompt. Never publish the token, full JSON, or debug API trace.

The comparator issues only `GET` calls for Sites, Device Roles, Device Types, Devices and existing Device Interfaces; checks exact site and name, manufacturer/model, type and role; refuses redirects and insecure TLS; and prevents pagination outside the configured origin. It reports objects that are missing, existing, ambiguously named, conflicting, or lacking prerequisites. It never applies these findings automatically.

**Not implemented:** creating devices/interfaces, device-type mapping overrides, VM/LXC import, MAC associations inside NetBox 4.7, VLAN objects, bridge/VLAN interfaces, IP assignments, primary IPs, cabling, deletion, scheduling.

## 3. Tests

```bash
python3 -m unittest discover -s tests -v
```

The module uses the Python standard library and can be tested offline. Proxmox and NetBox are not contacted by the unit tests.