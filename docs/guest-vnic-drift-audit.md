# Read-only guest interface drift audit

Separate, opt-in check for an existing Proxmox / NetBox guest inventory. It does not alter the existing host hardware systemd timer or Zabbix bridge.

On the Proxmox collector node, use the existing read-only NetBox API environment and run:

```bash
cd /root/netbox-inventory-toolkit
set -a
source /etc/netbox-inventory/drift.env
set +a
python3 netbox/audit_guest_nics.py --cluster YOUR_CLUSTER --expected-guests YOUR_COUNT --held-vmid YOUR_BASE_IMAGE_VMID --output-dir /var/lib/netbox-guest-audit
```

Every run reads fresh guest configurations with pvesh GET, and NetBox VM/interface objects via HTTPS GET, checks identity, allocated CPU/RAM, NIC names, bridge description and primary MAC, then writes an owner-only JSON report. Allowed intentional duplication for a stopped base-image guest is a documented exception; unexpected duplication or changes become drift.

Exit codes: 0 CLEAN, 1 DRIFT, 2 ERROR. Do not install a timer or Zabbix triggers until a live audit is independently verified. Reports contain internal VMIDs, so do not publish them.

If the API representation of `primary_mac_address` differs from what the NetBox read-only endpoint returns, the script fails closed rather than guessing. Always inspect reported errors before enabling scheduled monitoring.
