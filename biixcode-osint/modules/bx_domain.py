"""bx_domain.py
Simple domain reconnaissance helpers (example functions).
"""
import requests
from urllib.parse import urlparse

def get_domain_from_url(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc or parsed.path

def whois_lookup(domain: str) -> dict:
    """Placeholder WHOIS function — replace with a real WHOIS library/service."""
    # For a real implementation use python-whois or an external API.
    return {"domain": domain, "whois": "not_implemented"}

if __name__ == '__main__':
    print(get_domain_from_url('https://example.com/path'))
