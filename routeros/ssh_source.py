#!/usr/bin/env python3
"""Read-only RouterOS SSH JSON source for the IPAM audit.

Only two hard-coded RouterOS commands can be executed. Strict SSH host-key
checking and public-key-only authentication are mandatory. No shell=True,
remote scripting, configuration writes, credential output, or saved raw data.
"""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from routeros.ipam_audit import IPAMAuditError

_COMMANDS = {
    "/rest/interface/vlan":
        ":put [:serialize to=json value=[/interface vlan print as-value] "
        "options=json.no-string-conversion]",
    "/rest/ip/address":
        ":put [:serialize to=json value=[/ip address print as-value] "
        "options=json.no-string-conversion]",
}
_USER_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.-]{0,63}$")


def _private_regular_file(path: str, *, label: str) -> str:
    if not isinstance(path, str) or not path.startswith("/"):
        raise IPAMAuditError("Absolute " + label + " path required")
    p = Path(path)
    try:
        info = p.lstat()
    except OSError:
        raise IPAMAuditError("Cannot read " + label) from None
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
            info.st_mode & 0o077 or p.is_symlink()):
        raise IPAMAuditError("Unsafe " + label + " file permissions")
    return path


def _known_hosts_file(path: str) -> str:
    if not isinstance(path, str) or not path.startswith("/"):
        raise IPAMAuditError("Absolute known_hosts path required")
    p = Path(path)
    try:
        info = p.lstat()
    except OSError:
        raise IPAMAuditError("Missing SSH known_hosts") from None
    if not stat.S_ISREG(info.st_mode) or p.is_symlink():
        raise IPAMAuditError("Unsafe SSH known_hosts file")
    return path


class RouterOSSSHReader:
    """Produce RouterOS REST-style rows for routeros_snapshot() via SSH."""

    def __init__(self, *, host: str, username: str, identity_file: str,
                 known_hosts_file: str, timeout: int = 20):
        try:
            parsed = ipaddress.ip_address(host)
            if not isinstance(parsed, ipaddress.IPv4Address):
                raise ValueError()
        except (TypeError, ValueError):
            raise IPAMAuditError("RouterOS host must be literal IPv4") from None
        if not isinstance(username, str) or not _USER_RE.fullmatch(username):
            raise IPAMAuditError("Invalid SSH user")
        if type(timeout) is not int or not 5 <= timeout <= 120:
            raise IPAMAuditError("Invalid SSH deadline")
        self.host = str(parsed)
        self.username = username
        self.identity = _private_regular_file(identity_file, label="SSH identity")
        self.known_hosts = _known_hosts_file(known_hosts_file)
        self.timeout = timeout

    def listing(self, endpoint: str) -> list[dict]:
        if endpoint not in _COMMANDS:
            raise IPAMAuditError("Forbidden RouterOS command")
        argv = [
            "/usr/bin/ssh",
            "-F", "/dev/null",
            "-T",
            "-i", self.identity,
            "-o", "IdentitiesOnly=yes",
            "-o", "PreferredAuthentications=publickey",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "UserKnownHostsFile=" + self.known_hosts,
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=8",
            "-o", "ConnectionAttempts=1",
            "-o", "ForwardAgent=no",
            "-o", "ClearAllForwardings=yes",
            "-o", "PermitLocalCommand=no",
            "-o", "ProxyCommand=none",
            "-o", "ProxyJump=none",
            "-o", "ControlMaster=no",
            "-o", "LogLevel=ERROR",
            "--",
            self.username + "@" + self.host,
            _COMMANDS[endpoint],
        ]
        try:
            response = subprocess.run(
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=self.timeout, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise IPAMAuditError("RouterOS SSH command unavailable") from None
        if response.returncode != 0:
            # Deliberately do not log stderr: it may contain internal addresses.
            raise IPAMAuditError("RouterOS SSH read failed") from None
        if len(response.stdout) > 2_000_000:
            raise IPAMAuditError("Oversized RouterOS SSH response")
        try:
            data = json.loads(response.stdout)
        except (UnicodeError, ValueError):
            raise IPAMAuditError("Malformed RouterOS SSH JSON") from None
        if not isinstance(data, list) or len(data) > 50000 or any(
                not isinstance(rec, dict) for rec in data):
            raise IPAMAuditError("Unexpected RouterOS SSH JSON records")
        return data
