"""Principals, tokens, grants, the policy store and the access-log reader.

Design: docs/design/principals-and-grants.md.

One implementation of "may this principal do this?" shared by the server, the CLI's local mode and ``admin check``.
"""

from .accesslog import format_record, now_iso, read_records
from .errors import PolicyError
from .evaluate import admin_decision, can_admin, evaluate, explain, visible
from .legacy import migrate_v1, v1_admin_ids
from .models import ACTIONS, KINDS, Decision, Grant, Policy, Principal, Token
from .patterns import pattern_matches, validate_pattern, validate_tag
from .store import (
    PolicyEditor,
    admin_expiry_warning,
    check_lockout,
    check_lockout_change,
    dump_policy,
    edit_policy,
    empty_policy,
    has_usable_admin,
    load_policy,
    parse_duration,
    parse_duration_or_time,
    parse_policy,
    save_policy,
    validate_name,
    validate_policy,
)
from .tokens import (
    DUMMY_HASH,
    generate_token,
    hash_token,
    is_legacy_hash,
    is_valid_token_id,
    parse_token,
    validate_token_hash,
    verify_token_hash,
)

__all__ = [
    "ACTIONS",
    "DUMMY_HASH",
    "KINDS",
    "Decision",
    "Grant",
    "Policy",
    "PolicyEditor",
    "PolicyError",
    "Principal",
    "Token",
    "admin_decision",
    "admin_expiry_warning",
    "can_admin",
    "check_lockout",
    "check_lockout_change",
    "dump_policy",
    "edit_policy",
    "empty_policy",
    "evaluate",
    "explain",
    "format_record",
    "generate_token",
    "has_usable_admin",
    "hash_token",
    "is_legacy_hash",
    "is_valid_token_id",
    "load_policy",
    "migrate_v1",
    "now_iso",
    "parse_duration",
    "parse_duration_or_time",
    "parse_policy",
    "parse_token",
    "pattern_matches",
    "read_records",
    "save_policy",
    "validate_name",
    "validate_pattern",
    "validate_policy",
    "validate_tag",
    "v1_admin_ids",
    "validate_token_hash",
    "verify_token_hash",
    "visible",
]
