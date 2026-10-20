# RouterOS IPAM audit — offline prototype

This is an **offline, read-only comparison engine**, not an installed RouterOS collector, Zabbix integration, or systemd timer. No network I/O and no writes to MikroTik, Proxmox or NetBox are performed.

## Inputs

Provide two **privately collected, independently reviewed JSON snapshots**, each root-owned mode 0600 with timezone-aware `collected_at`. The RouterOS snapshot (`schema_version=routeros-ipam-0.1`) contains `vlans` records with `vid`, `name`, `parent`, `disabled` and `addresses` with `address` IPv4 CIDR, `interface`, `dynamic`, `disabled`. The NetBox snapshot (`schema_version=netbox-router-ipam-0.1`) contains VLAN `vid`/`prefix` records and assigned IPv4 `address`/`interface` records for **one verified router device**. Tests use documentation-only IP ranges.

The comparison checks approved counts, VLAN ID to gateway subnet mapping, static address/interface exact pairs, duplicate entries, snapshot freshness, disabled VLANs, unexpected dynamic addresses and explicitly approved dynamic exceptions. Snapshots older than 60 minutes are rejected by default. Only sanitized counts and categories are printed, not IP addresses. Exit codes: **0 CLEAN, 1 DRIFT, 2 ERROR**. Count mismatch/incomplete evidence is an error, not a clean audit.

Example once the two snapshot exporters have been implemented and independently validated:

    chmod 0600 /secure/routeros.json /secure/netbox.json
    python3 routeros/ipam_audit.py --router-snapshot /secure/routeros.json --netbox-snapshot /secure/netbox.json --expected-vlans YOUR_APPROVED_VLAN_COUNT --expected-static-addresses YOUR_APPROVED_STATIC_IP_COUNT

The CLI intentionally does not provide a dynamic address approval switch. Unexpected dynamic IPs return DRIFT; hardcoded or guessed exclusions are forbidden. Approved dynamic entries can be supplied to the Python `compare()` function only after an explicit review of address provenance.

### Limitations

No RouterOS SSH/API collector or NetBox API exporter has been deployed yet. Full RouterOS bridge VLAN tables, VLAN interfaces with multiple gateway prefixes, overlapping scopes, VRFs, routing state, and VM guest IPAM are outside this initial model. No changes to existing Proxmox audits or Zabbix services. Do not schedule this prototype before a live read-only collection and a complete baseline review.

Run offline unit tests with `python3 -m unittest discover -s tests -v`.
