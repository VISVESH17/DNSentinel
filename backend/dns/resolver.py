"""
Lightweight DNS resolver simulation.

A hackathon prototype doesn't need to run a full production-grade DNS
server on port 53. This module simulates the resolution step so the
demo can show "ALLOW -> real IP" vs "BLOCK -> sinkhole IP" without
needing raw sockets or root privileges. Swap this for dnspython /
CoreDNS integration in the full deployment (see docs/architecture.md).
"""
import random
import time

SINKHOLE_IP = "10.10.10.10"  # points to the internal "blocked" warning page


def resolve(domain: str, action: str) -> dict:
    """Simulate resolving `domain`, honoring the policy `action`."""
    start = time.perf_counter()

    if action == "BLOCK":
        ip = SINKHOLE_IP
        response_code = "BLOCKED"
    else:
        # Simulated upstream resolution (deterministic-ish fake IP for demo)
        ip = f"93.184.{random.randint(1,254)}.{random.randint(1,254)}"
        response_code = "NOERROR"

    latency_ms = round((time.perf_counter() - start) * 1000 + random.uniform(2, 15), 2)

    return {
        "domain": domain,
        "resolved_ip": ip,
        "response_code": response_code,
        "latency_ms": latency_ms,
    }
