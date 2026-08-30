"""
Query normalizer + basic lexical checks for incoming domain lookups.
This is the "Query Normalizer" module from the architecture diagram:
it canonicalizes the domain and extracts cheap signals (entropy, TLD,
subdomain depth) used later by the ML and risk-engine layers.
"""
import math
import re
from collections import Counter
from dataclasses import dataclass

SUSPICIOUS_TLDS = {"xyz", "top", "click", "gq", "tk", "ml", "cf", "work", "loan", "zip"}
SUSPICIOUS_KEYWORDS = {
    "login", "verify", "secure", "account", "update", "confirm",
    "bank", "wallet", "signin", "paypal", "password",
}


@dataclass
class NormalizedQuery:
    domain: str
    tld: str
    labels: list
    length: int
    subdomain_count: int
    digit_ratio: float
    entropy: float
    suspicious_tld: bool
    suspicious_keyword: bool


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def normalize(raw_domain: str) -> NormalizedQuery:
    domain = raw_domain.strip().lower().rstrip(".")
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0]

    labels = domain.split(".")
    tld = labels[-1] if len(labels) > 1 else ""
    subdomain_count = max(0, len(labels) - 2)

    core = domain.replace(".", "")
    digit_count = sum(ch.isdigit() for ch in core)
    digit_ratio = digit_count / len(core) if core else 0.0

    entropy = shannon_entropy(core)

    return NormalizedQuery(
        domain=domain,
        tld=tld,
        labels=labels,
        length=len(domain),
        subdomain_count=subdomain_count,
        digit_ratio=digit_ratio,
        entropy=entropy,
        suspicious_tld=tld in SUSPICIOUS_TLDS,
        suspicious_keyword=any(kw in domain for kw in SUSPICIOUS_KEYWORDS),
    )
