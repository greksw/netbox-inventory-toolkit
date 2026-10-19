# Zabbix 7.0: Proxmox ↔ NetBox daily drift monitoring

The Proxmox node already runs \`netbox-inventory-drift.service\` and timer,
and Zabbix Agent (classic) runs as \`zabbix\`.

Security boundaries:
- Collector and private report stay under \`/var/lib/netbox-inventory/\`,
  root-only (0600). Never chmod these files to be accessible by Zabbix.
- A root-run systemd \`ExecStopPost\` writes a **sanitized** atomic
  \`/var/lib/netbox-inventory-zabbix/metrics.json\` as \`root:zabbix 0640\`,
  within a \`root:zabbix 0750\` directory.
- The agent runs a simple read-only script and exposes **only integers**.
- No sudoers, API token access, or Zabbix Agent write permissions required.

## Installation on the Proxmox node

First, ensure the existing timer and manual audit both work. Then:

    cd /root/netbox-inventory-toolkit
    install -D -o root -g root -m 0755 \
      netbox/zabbix_bridge.py /usr/local/libexec/netbox-zabbix-bridge.py
    install -d -o root -g zabbix -m 0750 /var/lib/netbox-inventory-zabbix

Populate metrics from last known-good report (only if it is recent!):

    SERVICE_RESULT=success \
      python3 /usr/local/libexec/netbox-zabbix-bridge.py export
    runuser -u zabbix -- \
      python3 /usr/local/libexec/netbox-zabbix-bridge.py read status
    runuser -u zabbix -- \
      python3 /usr/local/libexec/netbox-zabbix-bridge.py read differences
    runuser -u zabbix -- \
      python3 /usr/local/libexec/netbox-zabbix-bridge.py read timestamp

A \`status=2\` means no usable recent report (not clean); run the
service once to refresh it.

Install Zabbix Agent UserParameters (no base config changes):

    install -m 0644 deploy/zabbix/netbox-inventory-drift.conf \
      /etc/zabbix/zabbix_agentd.conf.d/netbox-inventory-drift.conf
    zabbix_agentd -t netbox.audit.status
    zabbix_agentd -t netbox.audit.differences
    zabbix_agentd -t netbox.audit.timestamp
    systemctl restart zabbix-agent

Only after the reader works, enable post-audit export:

    install -d -m 0755 \
      /etc/systemd/system/netbox-inventory-drift.service.d
    install -m 0644 deploy/systemd/netbox-inventory-drift-zabbix.conf \
      /etc/systemd/system/netbox-inventory-drift.service.d/20-zabbix-bridge.conf
    systemctl daemon-reload
    systemd-analyze verify /etc/systemd/system/netbox-inventory-drift.service
    systemctl start netbox-inventory-drift.service
    journalctl -u netbox-inventory-drift.service -n 25 --no-pager

Export also runs if the main collector fails, and reports status=2.
The running timer requires no changes.

## Zabbix items on host

All **passive Zabbix agent** items with Type of information
**Numeric (unsigned)**, Update interval \`5m\`:

| Key | Description |
| --- | --- |
| \`netbox.audit.status\` | 0 clean, 1 drift, 2 error |
| \`netbox.audit.differences\` | Nonnegative drift count; ignore if status=2 |
| \`netbox.audit.timestamp\` | Unix seconds of latest audit completion; 0 if no status file |

Suggested trigger expressions (replace host name if different):

- Drift / Warning:
  \`last(/srv-pve01/netbox.audit.status)=1\`
- Audit error / High:
  \`last(/srv-pve01/netbox.audit.status)=2\`
- Audit stopped or stale / Average:
  \`now()-last(/srv-pve01/netbox.audit.timestamp)>93600\`
  (93600 seconds = 26 hours).
- Optional agent no data / Average:
  \`nodata(/srv-pve01/netbox.audit.status,15m)=1\`.

Set recovery when the expressions become false. Only enable notification
actions once the items report current values from the Zabbix server.

## Security and failure considerations

The status file never includes inventory identifiers. The agent does not
receive access to the private report or NetBox token. A malformed or
unavailable status file returns \`status=2\` and \`timestamp=0\`.
For an audit process error, the exporter emits status=2 and resets
differences=0 (unknown, not a claim of no drift). The monitoring trigger
must therefore always evaluate status separately.
