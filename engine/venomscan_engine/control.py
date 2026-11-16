from __future__ import annotations


class ScanCancelled(RuntimeError):
    """Raised when the operator cancels a running scan."""
