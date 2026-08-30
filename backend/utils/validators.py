"""Input validation helpers for API routes."""
import re

DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


def is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False
    return bool(DOMAIN_REGEX.match(domain.strip().lower().rstrip(".")))


def sanitize_domain(domain: str) -> str:
    return domain.strip().lower().rstrip(".")
