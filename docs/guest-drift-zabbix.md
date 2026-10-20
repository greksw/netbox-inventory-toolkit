# Guest drift Zabbix metric export (optional)

This bridge is separate from the existing physical-hardware NetBox audit metrics. Export only sanitized integers using a root-run systemd ExecStopPost hook. Keep private guest inventory and credentials inaccessible to Zabbix.

Three passive agent keys:

- netbox.guest.audit.status (0 CLEAN, 1 DRIFT, 2 ERROR)
- netbox.guest.audit.differences (nonnegative count; unknown when status=2)
- netbox.guest.audit.timestamp (Unix seconds of most recent audit attempt)

Run on the Proxmox collector node after a successfully verified guest-drift audit:

```sh
install -o root -g root -m 0755 netbox/zabbix_guest_bridge.py /usr/local/libexec/netbox-zabbix-guest-bridge.py
install -d -o root -g zabbix -m 0750 /var/lib/netbox-guest-audit-zabbix
SERVICE_RESULT=success python3 /usr/local/libexec/netbox-zabbix-guest-bridge.py export
runuser -u zabbix -- python3 /usr/local/libexec/netbox-zabbix-guest-bridge.py read status
install -m 0644 deploy/zabbix/netbox-guest-drift.conf /etc/zabbix/zabbix_agentd.conf.d/netbox-guest-drift.conf
zabbix_agentd -t netbox.guest.audit.status
zabbix_agentd -t netbox.guest.audit.differences
zabbix_agentd -t netbox.guest.audit.timestamp
systemctl restart zabbix-agent
```

Once verified, enable the post-audit export:

```sh
install -d -m 0755 /etc/systemd/system/netbox-guest-drift.service.d
install -m 0644 deploy/systemd/netbox-guest-drift-zabbix.conf /etc/systemd/system/netbox-guest-drift.service.d/20-zabbix-bridge.conf
systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/netbox-guest-drift.service
systemctl start netbox-guest-drift.service
journalctl -u netbox-guest-drift.service -n 25 --no-pager
```

The private report remains root-only. Export file is root:zabbix 0640 inside root:zabbix 0750. No notification actions are added. Configure Zabbix template/items/triggers separately after passive checks return values.
