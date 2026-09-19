"""
capabilities/__init__.py
------------------------
Universal Capability Architecture for Raven adaptive security assessment.

Defines modular assessment capabilities, capability registry, manifests,
and selection logic.
"""

from capabilities.registry import CapabilityRegistry

__all__ = ["CapabilityRegistry"]
