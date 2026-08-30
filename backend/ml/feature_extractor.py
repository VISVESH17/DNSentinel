"""
Lexical feature extraction for DGA (Domain Generation Algorithm)
classification. Mirrors the feature list from the SIH260003 playbook:
length, digit ratio, entropy, vowel/consonant ratio, hyphen count,
subdomain count, TLD signal.

Returns a plain dict so it can be reused for both training (pandas
DataFrame construction) and live inference (single-row prediction).
"""
import math
import re
from collections import Counter

VOWELS = set("aeiou")
SUSPICIOUS_TLDS = {"xyz", "top", "click", "gq", "tk", "ml", "cf", "work", "loan", "zip"}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def extract_features(domain: str) -> dict:
    domain = domain.strip().lower().rstrip(".")
    labels = domain.split(".")
    tld = labels[-1] if len(labels) > 1 else ""
    core = "".join(labels[:-1]) if len(labels) > 1 else domain

    length = len(core)
    digits = sum(ch.isdigit() for ch in core)
    alpha = sum(ch.isalpha() for ch in core)
    hyphens = core.count("-")
    vowels = sum(ch in VOWELS for ch in core if ch.isalpha())
    consonants = alpha - vowels
    unique_chars = len(set(core))

    return {
        "length": length,
        "digit_ratio": digits / length if length else 0.0,
        "alpha_ratio": alpha / length if length else 0.0,
        "unique_char_ratio": unique_chars / length if length else 0.0,
        "vowel_consonant_ratio": (vowels / consonants) if consonants else 0.0,
        "hyphen_count": hyphens,
        "subdomain_count": max(0, len(labels) - 2),
        "entropy": _entropy(core),
        "suspicious_tld": 1 if tld in SUSPICIOUS_TLDS else 0,
        "has_repeated_chars": 1 if re.search(r"(.)\1{2,}", core) else 0,
    }


FEATURE_ORDER = [
    "length", "digit_ratio", "alpha_ratio", "unique_char_ratio",
    "vowel_consonant_ratio", "hyphen_count", "subdomain_count",
    "entropy", "suspicious_tld", "has_repeated_chars",
]


def features_to_vector(features: dict) -> list:
    return [features[k] for k in FEATURE_ORDER]
