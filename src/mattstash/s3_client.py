"""
mattstash.s3_client
-------------------
S3 client functionality for MattStash.
"""

from typing import Optional

from .core import MattStash


def _ensure_scheme(u: Optional[str]) -> Optional[str]:
    """Ensure URL has a proper scheme (http/https)."""
    if not u:
        return u
    return u if u.startswith("http://") or u.startswith("https://") else f"https://{u}"


class S3ClientBuilder:
    """Handles creation of S3 clients from KeePass entries."""

    def __init__(self, mattstash: MattStash):
        self.mattstash = mattstash

    def create_client(
            self,
            title: str,
            *,
            region: str = "us-east-1",
            addressing: str = "path",  # "virtual" or "path"
            signature_version: str = "s3v4",
            retries_max_attempts: int = 10,
            verbose: bool = True,
    ):
        """
        Read a KeePass entry and return a configured boto3 S3 client.

        Entry mapping:
          - endpoint_url  <- entry.url  (required)
          - access_key    <- entry.username (required)
          - secret_key    <- entry.password (required)

        Raises ValueError on missing/invalid credential fields.
        """
        cred = self.mattstash.get(title, show_password=True)
        if cred is None:
            raise ValueError(f"[mattstash] Credential not found: {title}")

        endpoint = _ensure_scheme(cred.url)
        if not endpoint:
            raise ValueError(f"[mattstash] KeePass entry '{title}' has empty URL (S3 endpoint).")

        if not cred.username or not cred.password:
            raise ValueError(f"[mattstash] KeePass entry '{title}' missing username/password.")

        # Lazy imports to avoid hard dependency if caller never uses S3
        try:
            import boto3
            from botocore.config import Config
        except Exception as e:
            raise RuntimeError("[mattstash] boto3/botocore not available") from e

        if verbose:
            print(f"[mattstash] Using endpoint={endpoint}, region={region}, addressing={addressing}")

        cfg = Config(
            s3={"addressing_style": "virtual" if addressing == "virtual" else "path"},
            signature_version=signature_version,
            retries={"max_attempts": retries_max_attempts, "mode": "standard"},
        )

        session = boto3.session.Session()
        return session.client(
            "s3",
            endpoint_url=endpoint,
            region_name=region,
            aws_access_key_id=cred.username,
            aws_secret_access_key=cred.password,
            config=cfg,
        )
