"""Ready-to-plant bait files for a decoy.

Intruders go looking for particular files: ``~/.aws/credentials``, ``.env`` files, kubeconfigs,
SSH configs, documents with tempting names. Each file here carries one decoy and looks like the
real thing, so planting a decoy is a download and a copy, not a hand-edit.

* AWS key decoy: ``credentials`` (AWS CLI format) and ``production.env``.
* DNS decoy: ``kubeconfig``, ``ssh_config`` and ``production.env``. Each file puts a different
  label in front of the host name (``k8s-prod.``, ``bastion.``, ``db.``), and DNS hits record
  what is in front, so an alert says which file was used.
* API key decoy: ``production.env``.
* Document decoy: the Word document.

Everything other than the decoy (database passwords, secret keys) is filler derived from the
decoy's value: realistic, never valid anywhere, and the same on every download.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

from app.core.exceptions import ValidationError
from app.models.enums import HoneyTokenType
from app.models.honey_token import HoneyToken
from app.services import documents

TEXT = "text/plain; charset=utf-8"

KINDS: dict[HoneyTokenType, tuple[str, ...]] = {
    HoneyTokenType.AWS_KEY: ("aws-credentials", "env"),
    HoneyTokenType.DNS: ("kubeconfig", "ssh-config", "env"),
    HoneyTokenType.API_KEY: ("env",),
    HoneyTokenType.DOCUMENT: ("docx",),
}

# What each DNS bait file puts in front of the decoy's host name.
DNS_TAGS = {"kubeconfig": "k8s-prod", "ssh-config": "bastion", "env": "db"}

AUTHORS = ("J. Morgan", "A. Patel", "S. Chen", "M. Okafor", "L. Fischer", "R. Alvarez")


@dataclass(frozen=True)
class BaitFile:
    filename: str
    content_type: str
    content: bytes


def kinds_for(token: HoneyToken) -> list[str]:
    """The files this decoy can be downloaded as right now."""
    kinds = list(KINDS.get(token.token_type, ()))
    if token.token_type == HoneyTokenType.AWS_KEY and not _aws_keys(token):
        return []  # the worker has not created the key yet (or it was deleted)
    return kinds


def with_files(token: HoneyToken):
    """The API view of a decoy just created or rotated by an administrator, with its bait files."""
    from app.schemas.honey_token import HoneyTokenResponse
    view = HoneyTokenResponse.model_validate(token)
    view.files = kinds_for(token) if token.is_active else []
    return view


def _filler(token: HoneyToken, purpose: str, n: int = 32) -> str:
    """Stable, meaningless hex for passwords and keys that sit around the decoy."""
    return hashlib.sha256(f"honeyshield-bait:{purpose}:{token.token_value}".encode()).hexdigest()[:n]


def _aws_keys(token: HoneyToken) -> tuple[str, str] | None:
    meta = token.token_metadata or {}
    if meta.get("status") == "active" and meta.get("access_key_id") and meta.get("secret_access_key"):
        return meta["access_key_id"], meta["secret_access_key"]
    return None


def _host(token: HoneyToken, kind: str) -> str:
    return f"{DNS_TAGS[kind]}.{(token.token_metadata or {}).get('hostname')}"


def _aws_credentials(token: HoneyToken) -> str:
    key_id, secret = _aws_keys(token)
    profile = (token.token_metadata or {}).get("profile_name") or "default"
    return f"[{profile}]\naws_access_key_id = {key_id}\naws_secret_access_key = {secret}\nregion = us-east-1\n"


def _env(token: HoneyToken) -> str:
    db_host = _host(token, "env") if token.token_type == HoneyTokenType.DNS else "postgres-primary.internal"
    lines = [
        "# production - do not commit",
        "APP_ENV=production",
        f"DATABASE_URL=postgresql://app:{_filler(token, 'db', 24)}@{db_host}:5432/app",
        f"SECRET_KEY={_filler(token, 'secret', 48)}",
        "LOG_LEVEL=info",
    ]
    if token.token_type == HoneyTokenType.AWS_KEY:
        key_id, secret = _aws_keys(token)
        lines += ["AWS_DEFAULT_REGION=us-east-1", f"AWS_ACCESS_KEY_ID={key_id}", f"AWS_SECRET_ACCESS_KEY={secret}",
                  "S3_BUCKET=prod-app-uploads"]
    if token.token_type == HoneyTokenType.API_KEY:
        lines.append(f"API_KEY={token.token_value}")
    return "\n".join(lines) + "\n"


def _kubeconfig(token: HoneyToken) -> str:
    # No certificate-authority-data: kubectl parses that before connecting, and a made-up CA
    # would fail there, before the host name is ever looked up.
    return f"""apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://{_host(token, 'kubeconfig')}:6443
    insecure-skip-tls-verify: true
  name: prod
contexts:
- context:
    cluster: prod
    namespace: default
    user: deploy
  name: prod
current-context: prod
users:
- name: deploy
  user:
    token: {_filler(token, 'k8s', 64)}
"""


def _ssh_config(token: HoneyToken) -> str:
    return f"""Host bastion
    HostName {_host(token, 'ssh-config')}
    User deploy
    Port 22
    IdentityFile ~/.ssh/id_ed25519
    ServerAliveInterval 60

Host db-primary
    HostName 10.20.4.15
    User postgres
    ProxyJump bastion
"""


def _document_paragraphs(template: str, domain: str) -> list[str]:
    return {
        "vpn_access": [
            f"Gateway: vpn.{domain} (use the Contractors profile).",
            "Accounts are created for the duration of the engagement and disabled on the end date.",
            "Initial passwords are issued by the service desk; change them at first sign-in.",
            "Questions: IT service desk, extension 4410.",
        ],
        "salary_review": [
            "Draft for the leadership team only. Do not forward.",
            "Proposed adjustments by department are in the table circulated separately.",
            "Final figures need sign-off from Finance before letters go out.",
        ],
        "server_inventory": [
            "Production hosts, owners and break-glass admin accounts.",
            "Break-glass credentials are in the vault entry 'prod-admin'; rotate after every use.",
            f"Monitoring and backups: see the operations wiki at wiki.{domain}.",
        ],
        "board_minutes": [
            "Present: all directors. Apologies: none.",
            "1. Approval of previous minutes. 2. Financial update. 3. Acquisition discussion (confidential).",
            "Actions are recorded at the end of this document.",
        ],
    }.get(template, ["Internal use only."])


def _docx(token: HoneyToken) -> bytes:
    meta = token.token_metadata or {}
    if not meta.get("pixel_url", "").startswith(("https://", "http://")):
        raise ValidationError("This document decoy has no absolute pixel URL (PUBLIC_INGEST_BASE_URL was unset)")
    created = token.created_at or datetime.now(timezone.utc)
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    author = AUTHORS[int(_filler(token, "author", 8), 16) % len(AUTHORS)]
    return documents.build_docx(title=meta.get("title") or "Internal", image_url=meta["pixel_url"],
                                paragraphs=_document_paragraphs(meta.get("template", ""),
                                                                meta.get("domain_context") or "example.com"),
                                author=author, created=created)


def render(token: HoneyToken, kind: str) -> BaitFile:
    """The bait file ``kind`` for ``token``. Raises ValidationError if this decoy has no such file."""
    if kind not in kinds_for(token):
        raise ValidationError(f"No '{kind[:32]}' file for this decoy")
    if kind == "aws-credentials":
        return BaitFile("credentials", TEXT, _aws_credentials(token).encode())
    if kind == "env":
        return BaitFile("production.env", TEXT, _env(token).encode())
    if kind == "kubeconfig":
        return BaitFile("kubeconfig", TEXT, _kubeconfig(token).encode())
    if kind == "ssh-config":
        return BaitFile("ssh_config", TEXT, _ssh_config(token).encode())
    filename = (token.token_metadata or {}).get("filename") or "Document.docx"
    return BaitFile(filename, documents.DOCX_MIME, _docx(token))
