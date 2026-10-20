# Daily Proxmox/NetBox guest drift audit (read-only)

This optional service schedules the standalone QEMU/LXC audit, separate from the hardware inventory service. It performs only Proxmox `pvesh get` and NetBox HTTPS GET requests. It does not change guest configs, NetBox, host bridges or Zabbix.

## Requirements

- Confirm one successful manual run of `netbox/audit_guest_nics.py` with exit 0.
- Existing read-only NetBox API v2 credentials in root-only `/etc/netbox-inventory/drift.env` (including corporate TLS CA).
- The repository installed at `/root/netbox-inventory-toolkit`.
- Create root-only `/etc/netbox-inventory/guest-audit.env` with site-specific settings (example placeholders only):

```ini
GUEST_CLUSTER=YOUR_NETBOX_CLUSTER
GUEST_EXPECTED_GUESTS=YOUR_GUEST_COUNT
GUEST_HELD_VMID=YOUR_STOPPED_BASE_IMAGE_VMID
```

Never commit the deployment env or real guest JSON. The expected guest count intentionally makes the audit **fail closed** when an unknown VM is added or removed; adjust the approved baseline after review rather than silently accepting a new machine.

## Install after manual audit

On the cluster collector node as root:

```sh
install -d -m 0700 -o root -g root /var/lib/netbox-guest-audit
install -m 0644 -o root -g root deploy/systemd/netbox-guest-drift.service /etc/systemd/system/
install -m 0644 -o root -g root deploy/systemd/netbox-guest-drift.timer /etc/systemd/system/
chmod 0600 /etc/netbox-inventory/guest-audit.env
systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/netbox-guest-drift.service /etc/systemd/system/netbox-guest-drift.timer
systemctl start netbox-guest-drift.service
journalctl -u netbox-guest-drift.service -n 30 --no-pager
systemctl enable --now netbox-guest-drift.timer
systemctl list-timers --all netbox-guest-drift.timer
```

The guest timer is daily 05:45 with 0–15 minutes randomized delay, after the separate physical-node audit's 05:10 + 0–20 minutes window. Both write to distinct private directories. Exit 0 = clean; 1 = drift; 2 = error. `SuccessExitStatus=1` means a valid drift detection is not a systemd execution failure; always inspect `GUEST DRIFT:` and report categories.

Do not install Zabbix hooks until this timer has completed an actual scheduled run. Existing hardware metrics and triggers remain separate. External alert dispatch via Zabbix is not added.
