# RouterOS IPAM audit — offline prototype

The audit engine is **offline and read-only**. Experimental HTTPS GET-only source adapters are included for later manually approved integration; no production collector, Zabbix integration, or systemd timer is installed. No network I/O and no writes to MikroTik, Proxmox or NetBox are performed.

## Inputs

Provide two **privately collected, independently reviewed JSON snapshots**, each root-owned mode 0600 with timezone-aware `collected_at`. The RouterOS snapshot (`schema_version=routeros-ipam-0.1`) contains `vlans` records with `vid`, `name`, `parent`, `disabled` and `addresses` with `address` IPv4 CIDR, `interface`, `dynamic`, `disabled`. The NetBox snapshot (`schema_version=netbox-router-ipam-0.1`) contains VLAN `vid`/`prefix` records and assigned IPv4 `address`/`interface` records for **one verified router device**. Tests use documentation-only IP ranges.

The comparison checks approved counts, VLAN ID to gateway subnet mapping, static address/interface exact pairs, duplicate entries, snapshot freshness, disabled VLANs, unexpected dynamic addresses and explicitly approved dynamic exceptions. Snapshots older than 60 minutes are rejected by default. Only sanitized counts and categories are printed, not IP addresses. Exit codes: **0 CLEAN, 1 DRIFT, 2 ERROR**. Count mismatch/incomplete evidence is an error, not a clean audit.

Example once the two snapshot exporters have been implemented and independently validated:

    chmod 0600 /secure/routeros.json /secure/netbox.json
    python3 routeros/ipam_audit.py --router-snapshot /secure/routeros.json --netbox-snapshot /secure/netbox.json --expected-vlans YOUR_APPROVED_VLAN_COUNT --expected-static-addresses YOUR_APPROVED_STATIC_IP_COUNT

The CLI intentionally does not provide a dynamic address approval switch. Unexpected dynamic IPs return DRIFT; hardcoded or guessed exclusions are forbidden. Approved dynamic entries can be supplied to the Python `compare()` function only after an explicit review of address provenance.

### Limitations

Experimental GET-only RouterOS REST and NetBox snapshot adapters exist in `routeros/ipam_sources.py`, but no live credentials, production CLI wiring, scheduled deployment, or NetBox/RouterOS service changes have been made. Full RouterOS bridge VLAN tables, VLAN interfaces with multiple gateway prefixes, overlapping scopes, VRFs, routing state, and VM guest IPAM are outside this initial model. No changes to existing Proxmox audits or Zabbix services. Do not schedule this prototype before a live read-only collection and a complete baseline review.

Run offline unit tests with `python3 -m unittest discover -s tests -v`.

## Dynamic IPsec Mode Config addresses

A RouterOS address with `dynamic=true` **must not automatically be treated as an
unmanaged static IP discrepancy**. It can be installed by an IKEv2 client
Mode Config rather than a DHCP client. Before approving an exception, verify
all of the following directly on RouterOS:

1. The IPsec identity binds the expected peer to the client Mode Config
   (`responder=no`), and the active IKE peer is established with Phase 2.
2. A **dynamic** IPsec policy exists for the same peer and selects the
   observed local IPv4 address (typically a host /32 selector).
3. A **dynamic** `srcnat` rule marked as `ipsec mode-config` translates to
   that same IPv4 address and has the Mode Config's matching connection mark.
4. The address appears as dynamic under `/ip address`. Active-peer
   `dynamic-address` can be blank; an empty field alone neither confirms
   nor disproves Mode Config address usage.

Treat the peer, policy, NAT and assigned-address observations as one reviewed
runtime evidence set. For a subsequent collector, record only the minimum
required nonsecret attributes and verify their linkage before classifying a
dynamic address as an **expected VPN runtime assignment**. A changed or missing
expected assignment should be reported separately from static IPAM drift,
not silently ignored. The dynamic /32 policy selector and dynamically
installed interface address prefix length may be different; compare the
negotiated **IPv4 host address**, not the two CIDR strings verbatim.

**Current limitation:** the offline snapshot format does not include IPsec
policy/NAT evidence, so the default command still returns
`dynamic_review_required`. Do not mark all dynamic addresses as exempt, or
claim the existing prototype automatically verifies their IPsec provenance.
No live network changes are required for this classification.

## Experimental HTTPS adapters (not deployed)

`routeros/ipam_sources.py` provides `RouterOSReader`, `NetBoxReader`, `routeros_snapshot()`, and `netbox_snapshot()` for later integration. They restrict HTTPS origins, forbid redirects/proxies, verify server certificates, and use GET only. RouterOS endpoints: `/rest/interface/vlan` and `/rest/ip/address`. NetBox endpoints are allowlisted for device, interface, VLAN, Prefix and IP-address reads. The adapters require a **reviewed site, VLAN group and router identity**, and the NetBox API access should use a dedicated read-only token. RouterOS REST must be accessible through an already hardened `www-ssl` service with a dedicated read-only RouterOS user; do not enable HTTP `www` or weaken TLS to accommodate the collector.

These adapters have only synthetic/offline tests at this stage. Next, determine availability of TCP/443 from the auditor host, CA trust and least-privilege account access before live tests. Existing Proxmox drift timers and Zabbix agents remain untouched.

## SSH collection on dedicated monitoring host (experimental)

`routeros/ssh_source.py` implements `RouterOSSSHReader` with exactly two allowlisted RouterOS commands, serializing `/interface vlan print as-value` and `/ip address print as-value` to JSON. It is compatible with the existing `routeros_snapshot()` transformer. It uses a root-private SSH identity, an explicitly verified `known_hosts` file, `StrictHostKeyChecking=yes`, no SSH agent/forwarding/proxies and no passwords. It does not run arbitrary user-supplied RouterOS commands. It is **not yet installed or invoked by any timer**.

The actual monitoring host should be checked for Python 3.11+, the trusted NetBox corporate CA, and a dedicated RouterOS `ssh,read` identity. Do not reuse or modify existing telemetry identities. The next phase is to validate the SSH adapter manually from the monitoring host, then verify the NetBox API serialization and connect the two to the offline compare engine. Dynamic IPsec Mode Config entries remain review-required until automated provenance tests exist.
