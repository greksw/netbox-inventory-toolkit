# Daily Proxmox-to-NetBox read-only drift audit

Runs on **one corporate Proxmox cluster node** as root to access pvesh,
DMI, and physical NIC sysfs on peers through preconfigured verified SSH.
NetBox is queried via HTTPS using a scoped **read-only v2 API token**.
No NetBox device, interface, VM or IPAM records are written.

## Prerequisites

1. Existing v0.3 collector passed cluster-wide checks.
2. Approved URL, TLS root trust, and NetBox token with GET/view privileges
   for Device and Interface. The token **must not** have write permissions.
3. DNS resolution and routing from PVE to NetBox. Example corporate host
   might resolve as netbox.corp.example; do not substitute a guessed CA path.
4. Confirm API response contains interface `mac_address` or
   `primary_mac_address.mac_address` for the installed NetBox version.
   Unknown response shapes abort the audit rather than reporting a clean
   comparison. No TLS verification bypass is supported.

## First manually, without a timer

On the corporate Proxmox node, create a private environment file, for
example `/etc/netbox-inventory/drift.env`, with mode 0600. Use your actual
NetBox origin, read-only token, and optional corporate root CA certificate.

    NETBOX_URL=https://netbox.corp.example
    NETBOX_TOKEN=nbt_your_read_only_token_id.your_secret
    NETBOX_CA_FILE=/path/to/corporate-ca.pem

For the first manual run, load the environment from this file in a root-only
shell and run (no --inventory means fresh pvesh and SSH collection):

    set -a
    . /etc/netbox-inventory/drift.env
    set +a
    python3 netbox/drift_audit.py \
      --output-dir /var/lib/netbox-inventory \
      --cluster-label corporate-pve \
      --site-slug fm-office --role-slug hypervisor --expected-nodes 9
    unset NETBOX_TOKEN

The command creates `source-latest.json` and `drift-latest.json` with
mode 0600, in a private folder. Console output includes only counts and
change types; restricted report JSON can contain internal hostnames/interface
names, not raw serial/MAC values.

**Exit codes:** 0 = no drift; 1 = detected drift; 2 = error (pvesh, SSH,
TLS/API, unknown API shape). Never treat 2 as "in sync".

## Enable the systemd timer after a clean manual trial

Copy the two example units under `deploy/systemd/` to
`/etc/systemd/system/`; check their `ExecStart` paths and ensure this
repository is installed in `/root/netbox-inventory-toolkit`.

The systemd service uses `EnvironmentFile=/etc/netbox-inventory/drift.env`,
runs as root (required by pvesh and SSH keys), and only considers exit 1 a
successful **audit execution** (not a clean state). Journald still reports
`STATUS: DRIFT` for dashboards/alarms.

    systemctl daemon-reload
    systemctl start netbox-inventory-drift.service
    journalctl -u netbox-inventory-drift.service -n 40 --no-pager
    systemctl enable --now netbox-inventory-drift.timer
    systemctl list-timers --all | grep netbox-inventory-drift

The timer runs once daily with random delay for load distribution. No automatic
apply or NetBox POST/PATCH/DELETE is implemented.

## Monitoring integration

Watch the service's latest result and `drift-latest.json` status:
`clean`, `drift`, or `error`. Add a Zabbix item/Prometheus collector
later after validating the live run. Alerts should distinguish drift from
collection errors. Never export secrets, raw JSON inventory, or authentication
headers to logging.
