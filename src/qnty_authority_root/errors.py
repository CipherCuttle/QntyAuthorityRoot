"""Fail-closed error taxonomy for the authority receipt issuer."""

from __future__ import annotations


class AuthorityRootError(Exception):
    """Base class for all issuer failures."""


class CanonicalFormError(AuthorityRootError):
    """An input was not in the frozen canonical representation."""


class IssuancePolicyError(AuthorityRootError):
    """An issuer policy or request violated a V0 boundary."""


class IssuanceConflictError(IssuancePolicyError):
    """A request id was rebound to different canonical content."""


class DatabaseError(AuthorityRootError):
    """The append-only issuance ledger could not be admitted or committed."""
