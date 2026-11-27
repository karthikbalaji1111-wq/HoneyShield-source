"""Active Directory decoy generator: a domain account nobody uses.

Generation picks the account's name, description and (by default) a service principal name, and
the decoy's bait files carry a setup script that creates the account on a domain controller with
a long random password that is generated there and never leaves it. Nobody has a reason to touch
the account, so anything that does is an intruder: signing in with it (a password spray, a guess
from a leaked list), asking for a Kerberos ticket for its SPN (Kerberoasting) or, when read
auditing is on, reading it while enumerating the directory (BloodHound, PowerView, ldapsearch).

The domain controllers report what they see through HoneyShield's signed integration channel
(app/services/directory.py), so HoneyShield never needs a connection into the customer's network.

The decoy's value is an opaque id (``ad-`` + 32 hex): account names are chosen to look ordinary and
two customers may well use the same one, while honey_tokens.token_value is globally unique.
"""
from __future__ import annotations

import re
import secrets
from typing import Any, Mapping

from app.core.exceptions import ValidationError
from app.schemas.generation import GeneratedTokenData
from app.services.generation.base import BaseGenerator

# (sAMAccountName, display name, description, SPN service/host:port or None). Names an intruder
# expects to find and wants: backup and SQL service accounts, old admin accounts, deployment tools.
PROFILES: tuple[tuple[str, str, str, str | None], ...] = (
    ("svc_sqlbackup", "SQL Backup Service", "SQL Server backup agent - do not disable", "MSSQLSvc/sqlbak01:1433"),
    ("svc_veeam", "Veeam Backup Service", "Veeam B&R service account", "HTTP/veeam01"),
    ("svc_sccm_push", "SCCM Client Push", "SCCM client push installation account", "HTTP/sccm01"),
    ("adm_helpdesk", "Helpdesk Admin", "Shared helpdesk admin - password in IT vault", None),
    ("svc_exchange_old", "Exchange Legacy Service", "Legacy Exchange 2013 service account", "exchangeMDB/exch13"),
    ("svc_reporting", "Reporting Services", "SSRS service account", "MSSQLSvc/reports01:1433"),
    ("svc_ansible", "Ansible Automation", "Ansible WinRM account for patching", "WSMAN/mgmt01"),
    ("it_admin_temp", "IT Admin (temporary)", "Temporary admin for migration project", None),
)

#: sAMAccountName: at most 20 characters, none of "/\\[]:;|=,+*?<>@ or spaces. HoneyShield is stricter:
#: letters, digits, dot, underscore and hyphen, starting with a letter.
ACCOUNT_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,19}$")
SPN_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,30}/[A-Za-z0-9][A-Za-z0-9.-]{0,62}(:[0-9]{1,5})?$")
TEXT_RE = re.compile(r"^[A-Za-z0-9 .,()&_/-]{1,128}$")

AD_DETECTION = {
    "status": "CUSTOMER_HOOK",
    "rule": "The HoneyShield collector on each domain controller reports every sign-in attempt with the "
            "account (Kerberos, NTLM, interactive or network), every Kerberos service ticket requested for "
            "its SPN and, when read auditing is on, every read of the account object.",
    "shows": "The domain controller, the source address and workstation, the Windows event, the failure "
             "code and, for ticket requests and reads, the account that did it.",
    "delay": "The collector runs every minute.",
    "not_detected": "Domain controllers without the collector or without the audit policy; enumeration "
                    "without read auditing; an attacker who sees the account and leaves it alone.",
    "docs": "docs/active-directory-decoys.md",
}


def _numbered_spn(spn: str, n: int) -> str:
    """sqlbak01 -> sqlbak02, exch13 -> exch13-2: SPNs are unique in a forest."""
    service, rest = spn.split("/", 1)
    host, sep, port = rest.partition(":")
    host = host.replace("01", f"{n:02d}", 1) if "01" in host else f"{host}-{n}"
    return f"{service}/{host}{sep}{port}"


def _text(params: dict[str, Any], key: str, pattern: re.Pattern[str], what: str) -> str | None:
    value = params.get(key)
    if value is None or value == "":
        return None
    if not isinstance(value, str) or not pattern.match(value.strip()):
        raise ValidationError(f"{what} is not valid")
    return value.strip()


class AdAccountGenerator(BaseGenerator):
    @staticmethod
    def _profile(avoid: Any) -> tuple[str, str, str, str | None]:
        """A profile whose name the project does not use yet (``avoid_names``: lower-case names in use)."""
        taken = {str(n).lower() for n in avoid}
        free = [p for p in PROFILES if p[0] not in taken]
        if free:
            return secrets.choice(free)
        name, display, description, spn = secrets.choice(PROFILES)
        for n in range(2, 100):  # svc_veeam2, svc_veeam3, ...: how real second accounts get named
            if f"{name}{n}" not in taken:
                return f"{name}{n}", f"{display} {n}", description, spn and _numbered_spn(spn, n)
        raise ValidationError("This project has too many Active Directory decoys with generated names")

    def generate(
        self,
        project_domain: str,
        params: dict[str, Any],
        ingest_base_url: str | None = None,
        paths: Mapping[str, str] | None = None,
        dns_zone: str | None = None,
    ) -> GeneratedTokenData:
        name, display, description, spn = self._profile(params.get("avoid_names") or ())
        chosen = _text(params, "account_name", ACCOUNT_NAME_RE, "account_name (1-20 letters, digits, . _ -)")
        if chosen:
            known = next((p for p in PROFILES if p[0] == chosen.lower()), None)
            if known:
                name, display, description, spn = known
            else:
                # An SPN that matches the name: svc_backup_legacy -> HTTP/backup-legacy01
                host = re.sub(r"[^a-z0-9]+", "-", re.sub(r"^(svc|adm|sa|srv)[_.-]", "", chosen.lower())).strip("-")
                name, display, spn = chosen, chosen, f"HTTP/{(host or 'app')[:28]}01"
        display = _text(params, "display_name", TEXT_RE, "display_name") or display
        description = _text(params, "description", TEXT_RE, "description") or description
        if params.get("spn") is False or params.get("spn") == "":
            spn = None
        else:
            spn = _text(params, "spn", SPN_RE, "spn (service/host[:port])") or spn
        audit_reads = params.get("audit_reads") is True
        admin_count = params.get("admin_count", True) is not False
        return GeneratedTokenData(
            token_value="ad-" + secrets.token_hex(16),
            label=f"AD account {name}",
            metadata={
                "account_name": name,
                "display_name": display,
                "description": description,
                # Host part only; the setup script adds the domain's DNS name on the controller.
                "spn": spn,
                "audit_reads": audit_reads,
                "admin_count": admin_count,
                "domain_context": project_domain,
                "detection": dict(AD_DETECTION),
            },
        )
