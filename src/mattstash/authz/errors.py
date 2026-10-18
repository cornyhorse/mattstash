"""Errors raised by :mod:`mattstash.authz`."""


class PolicyError(ValueError):
    """A policy, pattern, token or edit is invalid.

    It subclasses ``ValueError`` so callers that already catch ``ValueError`` around the v1 key-policy loader keep
    working. Messages never contain a token plaintext or a token hash: they are shown to users and written to logs.
    """
