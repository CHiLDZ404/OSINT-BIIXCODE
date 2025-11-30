"""bx_recon.py
High-level recon flows that call other module functions.
This file demonstrates how to import and use the small helpers.
"""
from .bx_domain import get_domain_from_url, whois_lookup
from .bx_email import is_valid_email, domain_from_email
from .bx_ip import is_valid_ip, ip_version

def recon_target(target: str) -> dict:
    # very simple dispatch based on target content
    out = {'target': target}
    if '@' in target and is_valid_email(target):
        out['type'] = 'email'
        out['email_domain'] = domain_from_email(target)
    elif any(c.isalpha() for c in target) and '.' in target:
        out['type'] = 'domain'
        out['domain'] = get_domain_from_url(target)
        out['whois'] = whois_lookup(out['domain'])
    elif is_valid_ip(target):
        out['type'] = 'ip'
        out['ip_version'] = ip_version(target)
    else:
        out['type'] = 'unknown'
    return out

if __name__ == '__main__':
    print(recon_target('test@example.com'))
