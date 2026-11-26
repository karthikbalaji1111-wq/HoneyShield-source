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
}

BY_DECOY_TYPE: dict[str, tuple[str, ...]] = {
    "URL": ("T1595.003", "T1213"),      # hidden paths: found by wordlist scanning or in internal docs
    "LINK": ("T1213",),                 # links hidden in wikis and internal pages
    "PIXEL": ("T1114", "T1005"),        # decoy emails and documents being read
    "DOCUMENT": ("T1005", "T1039"),     # decoy files opened from a disk or a share
    "API_KEY": ("T1552.001", "T1078"),  # a key read from a file, then used
    "DNS": ("T1552.001", "T1083"),      # a host name read from a config file, then connected to
    "AWS_KEY": ("T1552.001", "T1078.004"),
    "FORM_FIELD": (),
}


def techniques_for(decoy_type: str | None) -> list[dict[str, Any]]:
    """[{"id", "name", "tactics", "url"}] for a decoy type; empty when nothing fits."""
    out = []
    for tid in BY_DECOY_TYPE.get(decoy_type or "", ()):
        name, tactics = TECHNIQUES[tid]
        out.append({"id": tid, "name": name, "tactics": list(tactics),
                    "url": "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"})
    return out


def technique_ids(decoy_type: str | None) -> list[str]:
    return list(BY_DECOY_TYPE.get(decoy_type or "", ()))
