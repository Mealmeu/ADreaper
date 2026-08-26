"""ADreaper — a modern, modular Active Directory penetration-testing framework.

Authorized security testing only. See DISCLAIMER.md.
"""

__version__ = "0.1.0"
__author__ = "Mealmeu"

# Convenience re-exports for module authors.
from adreaper.core.module import (  # noqa: E402,F401
    BaseModule,
    Option,
    OptionType,
    ModuleResult,
    Finding,
    Severity,
)
from adreaper.core.context import EngagementContext, Credential, Target  # noqa: E402,F401

__all__ = [
    "__version__",
    "BaseModule",
    "Option",
    "OptionType",
    "ModuleResult",
    "Finding",
    "Severity",
    "EngagementContext",
    "Credential",
    "Target",
]
