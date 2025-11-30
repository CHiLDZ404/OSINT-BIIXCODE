"""bx4me.py
Simple CLI entrypoint to run recon on a target.
Usage: python bx4me.py target
"""
import sys
from modules.bx_recon import recon_target

def main():
    if len(sys.argv) < 2:
        print('Usage: python bx4me.py <target>')
        sys.exit(1)
    target = sys.argv[1]
    result = recon_target(target)
    import json
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()
