"""bx_ip.py
Simple IP helpers.
"""
import ipaddress

def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def ip_version(ip: str) -> int:
    try:
        return ipaddress.ip_address(ip).version
    except ValueError:
        return 0
