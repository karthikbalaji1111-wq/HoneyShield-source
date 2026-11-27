"""MITRE ATT&CK techniques a decoy hit points to.

A decoy only fires when someone did what the decoy was planted for, so its type says which
technique was most likely used: an AWS key in a credentials file that gets used is T1552.001
(found in a file) followed by T1078.004 (used as a cloud account). These are the labels SOC
tooling groups and reports on; they are a starting point for triage, not a verdict.

Names and tactics follow ATT&CK Enterprise (https://attack.mitre.org/). Form honeypots map to
nothing: a bot filling a hidden field is spam or scanning noise that ATT&CK does not model.
"""
from __future__ import annotations

from typing import Any

# id -> (name, tactics)
TECHNIQUES: dict[str, tuple[str, tuple[str, ...]]] = {
    "T1552.001": ("Unsecured Credentials: Credentials In Files", ("Credential Access",)),
    "T1078": ("Valid Accounts", ("Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access")),
    "T1078.004": ("Valid Accounts: Cloud Accounts",
                  ("Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access")),
    "T1083": ("File and Directory Discovery", ("Discovery",)),
    "T1595.003": ("Active Scanning: Wordlist Scanning", ("Reconnaissance",)),
    "T1213": ("Data from Information Repositories", ("Collection",)),
    "T1005": ("Data from Local System", ("Collection",)),
    "T1039": ("Data from Network Shared Drive", ("Collection",)),
    "T1114": ("Email Collection", ("Collection",)),
    "T1558.003": ("Steal or Forge Kerberos Tickets: Kerberoasting", ("Credential Access",)),
    "T1110": ("Brute Force", ("Credential Access",)),
    "T1078.002": ("Valid Accounts: Domain Accounts",
                  ("Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access")),
    "T1087.002": ("Account Discovery: Domain Account", ("Discovery",)),
}

BY_DECOY_TYPE: dict[str, tuple[str, ...]] = {
    "URL": ("T1595.003", "T1213"),      # hidden paths: found by wordlist scanning or in internal docs
    "LINK": ("T1213",),                 # links hidden in wikis and internal pages
    "PIXEL": ("T1114", "T1005"),        # decoy emails and documents being read
    "DOCUMENT": ("T1005", "T1039"),     # decoy files opened from a disk or a share
    "API_KEY": ("T1552.001", "T1078"),  # a key read from a file, then used
    "DNS": ("T1552.001", "T1083"),      # a host name read from a config file, then connected to
    "AWS_KEY": ("T1552.001", "T1078.004"),
    "AD_ACCOUNT": ("T1087.002", "T1110", "T1558.003"),  # found by enumeration, then tried or roasted
    "FORM_FIELD": (),
}

#: Active Directory decoys: what the domain controller saw says which technique it was. The event's
#: request_path is "ad/<kind>" (app/services/directory.py).
BY_DIRECTORY_EVENT: dict[str, tuple[str, ...]] = {
    "ad/service-ticket": ("T1558.003",),   # 4769: a ticket for the decoy's SPN, the Kerberoasting step
    "ad/preauth-failure": ("T1110",),      # 4771: Kerberos sign-in with a wrong password
    "ad/tgt-failure": ("T1110",),          # 4768 failed
    "ad/logon-failure": ("T1110",),        # 4625
    "ad/ntlm-failure": ("T1110",),         # 4776 failed
    "ad/logon-success": ("T1078.002",),    # 4624: someone has the password
    "ad/tgt-issued": ("T1078.002",),       # 4768 succeeded
    "ad/ntlm-validated": ("T1078.002",),   # 4776 succeeded
    "ad/object-read": ("T1087.002",),      # 4662: the account object was read (enumeration)
}


def technique_ids(decoy_type: str | None, request_path: str | None = None) -> list[str]:
    """Technique ids for a decoy type, narrowed by the event where the event says more."""
    if decoy_type == "AD_ACCOUNT" and request_path in BY_DIRECTORY_EVENT:
        return list(BY_DIRECTORY_EVENT[request_path])
    return list(BY_DECOY_TYPE.get(decoy_type or "", ()))


def techniques_for(decoy_type: str | None, request_path: str | None = None) -> list[dict[str, Any]]:
    """[{"id", "name", "tactics", "url"}] for a decoy type (and event); empty when nothing fits."""
    out = []
    for tid in technique_ids(decoy_type, request_path):
        name, tactics = TECHNIQUES[tid]
        out.append({"id": tid, "name": name, "tactics": list(tactics),
                    "url": "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"})
    return out
