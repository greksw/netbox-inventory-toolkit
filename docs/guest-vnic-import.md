# Guarded VMInterface importer (review before production apply)

This module takes a private, locally generated NetBox guest NIC preview. It does not modify Proxmox and does not invent VLAN assignments or change host bridge configuration.

Run it through NetBox 4.7 Django manage.py shell. Dry-run is the default. To apply, supply deployment-specific cluster name, exact expected VM/interface/MAC counts, explicit held VMIDs, and confirmation. Do not store these values or real inventory in the public repository.

The script validates preview freshness, expected object counts, duplicate MAC handling, the VMID-to-NetBox mapping, absence of pre-existing VM interfaces or conflicting MAC records, and executes approved changes inside one PostgreSQL transaction. The method set_primary_mac_address_from_value() is used for primary MACs.

Before any production write: create and verify a fresh PostgreSQL backup, transfer preview JSON privately (mode 0600), confirm live Django dry-run, and explicitly authorize apply. This module never creates virtual machines, VLANs, IP addresses, or Linux bridges.

Proxmox bridge names are stored as textual metadata in the new NetBox interface description, not as NetBox VMInterface.bridge references.
