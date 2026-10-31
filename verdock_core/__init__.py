"""verdock_core: policy, approvals, invariants, outcomes, signed receipts and an egress gateway.

Import the submodules directly, for example::

    from verdock_core.policy import load_policy, decide
    from verdock_core.receipts import ReceiptLog, verify_log
"""

from .errors import PolicyError, Refused

__version__ = "0.2.0"

__all__ = ["__version__", "PolicyError", "Refused"]
