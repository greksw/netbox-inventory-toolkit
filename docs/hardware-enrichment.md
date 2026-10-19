# Guarded enrichment of existing NetBox hardware

This module is for NetBox 4.7.x, where the interface method
set_primary_mac_address_from_value() has been tested in a manual, transactional
hardware enrichment. The generic module in this repository still requires a
read-only production test before any optional apply.

Only existing physical devices and matching interfaces are eligible. It can
fill blank device serials and assign current physical NIC primary MACs.
It will not create devices, interfaces, VLANs, IPs, virtual machines or cables,
and it will not overwrite differing serials or primary MACs.

Run it in the NetBox Django shell. Copy the script to a protected location
on the NetBox host, and ensure the netbox OS user can read both the script
and the private inventory file. Keep internal inventory files OUT of GitHub.

## Example of read-only rerun after an earlier enrichment

The following commands show the generic shape; replace paths and site/role
slugs with the real values from your deployment. Use a verified local copy
of the script, not an unreviewed network download.

    runuser -u netbox -- /opt/netbox/venv/bin/python \
      /opt/netbox/netbox/manage.py shell -c \
      "from runpy import run_path; run_path('/path/to/enrich_existing.py')['run'](
        '/path/to/proxmox-inventory-v03.json',
        site_slug='office', role_slug='hypervisor',
        expected_devices=9, expected_interfaces=362,
        expected_serials=7, expected_macs=20)"

After prior successful import: serials_to_add = 0, macs_to_assign = 0.
All seven existing serials and twenty MACs should already match.

## Optional apply

Only after a DB backup and a dry-run with no errors, and after pausing other
jobs touching the same NetBox hardware records, call the same run function
with apply=True and confirmation='APPLY_EXISTING_HARDWARE_ONLY'. Applying
writes in a single Django atomic transaction. It will fail closed when the
source or current NetBox state differs from reviewed expectations.

Offline tests do not exercise the live Django database code path. Do not use
this generic script to repeat the completed manual enrichment needlessly.
