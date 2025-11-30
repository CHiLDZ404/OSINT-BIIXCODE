"""bx_email.py
Email address utilities and simple validation.
"""
import re

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def is_valid_email(email: str) -> bool:
    return bool(EMAIL_RE.match(email))

def domain_from_email(email: str) -> str:
    return email.split('@')[-1] if '@' in email else ''
