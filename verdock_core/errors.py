"""Exceptions shared by every verdock_core module."""


class Refused(Exception):
    """An action was refused by a policy, an approval check or an invariant.

    The message is a short reason meant for logs and for the person who
    asked for the action.
    """


class PolicyError(ValueError):
    """A policy file or policy object is outside the supported format."""
