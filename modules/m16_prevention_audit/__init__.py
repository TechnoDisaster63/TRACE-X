"""M16 immutable prevention audit and action-lifecycle model."""
from .lifecycle import (
    ActionLifecycle,
    AuditEvent,
    LifecycleError,
    create_lifecycle,
    transition_lifecycle,
    verify_lifecycle_integrity,
)

__all__ = [
    "ActionLifecycle", "AuditEvent", "LifecycleError", "create_lifecycle",
    "transition_lifecycle", "verify_lifecycle_integrity",
]
