"""
adapters/target_adapters/network_adapter.py
-------------------------------------------
Target adapter for IP addresses, CIDR ranges, and network hosts.
"""

from __future__ import annotations

import ipaddress

from engine_models.target import Target, TargetType


class NetworkTargetAdapter:
    """Adapts network IP addresses and CIDRs into Target models."""

    @classmethod
    def can_handle(cls, raw_input: str) -> bool:
        clean = raw_input.strip()
        try:
            if "/" in clean:
                ipaddress.ip_network(clean, strict=False)
                return True
            else:
                parts = clean.split(":")
                host_part = parts[0]
                if host_part.lower() in ("localhost", "127.0.0.1", "0.0.0.0"):
                    return True
                ipaddress.ip_address(host_part)
                return True
        except ValueError:
            pass

        # Check for host:port pattern (e.g., myservice:8080 or localhost:6379)
        if ":" in clean and not clean.startswith("http://") and not clean.startswith("https://"):
            parts = clean.split(":")
            if len(parts) == 2 and parts[1].isdigit() and 1 <= int(parts[1]) <= 65535:
                return True
        return False

    @classmethod
    def adapt(cls, raw_input: str) -> Target:
        clean = raw_input.strip()
        if "/" in clean:
            target_type = TargetType.NETWORK_RANGE
        else:
            target_type = TargetType.NETWORK_SERVICE

        return Target(
            raw_input=raw_input,
            target_type=target_type,
            entrypoints=[clean],
            metadata={"address": clean},
        )
