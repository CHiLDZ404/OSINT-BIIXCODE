#!/usr/bin/env python3
"""
BIIXCODE / BX4ME OSINT Framework
Advanced Open Source Intelligence Tool
Author: BiixCode Team
Version: 2.0
"""

import argparse
import sys
import os
from datetime import datetime
from modules.bx_domain import BXDomain
from modules.bx_social import BXSocial
from modules.bx_email import BXEmail
from modules.bx_ip import BXIP
from modules.bx_recon import BXRecon

class BiixCodeOSINT:
    def __init__(self):
        self.version = "2.0"
        self.author = "BiixCode"
        self.banner()
        
    def banner(self):
        print(f"""
    ╔══════════════════════════════════════════════╗
    ║           🛡️ BIIXCODE OSINT FRAMEWORK 🛡️           ║
    ║                 v{self.version} - {self.author}              ║
    ║                                              ║
    ║     ██████╗ ██╗██╗██╗  ██╗ ██████╗██████╗   ║
    ║     ██╔══██╗██║██║╚██╗██╔╝██╔════╝██╔══██╗  ║
    ║     ██████╔╝██║██║ ╚███╔╝ ██║     ██║  ██║  ║
    ║     ██╔══██╗██║██║ ██╔██╗ ██║     ██║  ██║  ║
    ║     ██████╔╝██║██║██╔╝ ██╗╚██████╗██████╔╝  ║
    ║     ╚═════╝ ╚═╝╚═╝╚═╝  ╚═╝ ╚═════╝╚═════╝   ║
    ╚══════════════════════════════════════════════╝
        """)

    def run_all_modules(self, target, output_file=None):
        """Run all OSINT modules against target"""
        print(f"[BX4ME] Starting comprehensive OSINT on: {target}")
        results = {}
        
        # Domain Intelligence
        if '.' in target and not target.replace('.', '').isdigit():
            print("\n[🔍] Running Domain Intelligence...")
            domain_tool = BXDomain()
            results['domain'] = domain_tool.investigate(target)
        
        # Social Media Recon
        print("\n[👤] Running Social Media Intelligence...")
        social_tool = BXSocial()
        results['social'] = social_tool.find_profiles(target)
        
        # Email Analysis
        if '@' in target:
            print("\n[📧] Running Email Intelligence...")
            email_tool = BXEmail()
            results['email'] = email_tool.analyze_email(target)
        
        # IP Investigation
        if target.replace('.', '').isdigit():
            print("\n[🌐] Running IP Intelligence...")
            ip_tool = BXIP()
            results['ip'] = ip_tool.investigate(target)
        
        # Advanced Recon
        print("\n[🕵️] Running Advanced Reconnaissance...")
        recon_tool = BXRecon()
        results['recon'] = recon_tool.comprehensive_scan(target)
        
        return results

def main():
    tool = BiixCodeOSINT()
    
    parser = argparse.ArgumentParser(description='BIIXCODE OSINT Framework')
    parser.add_argument('target', help='Target domain, IP, email, or username')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-m', '--module', choices=['domain', 'social', 'email', 'ip', 'all'], 
                       default='all', help='Specific module to run')
    
    args = parser.parse_args()
    
    try:
        results = tool.run_all_modules(args.target, args.output)
        
        # Save results if output specified
        if args.output:
            with open(args.output, 'w') as f:
                f.write(f"BIIXCODE OSINT Report - {datetime.now()}\n")
                f.write(f"Target: {args.target}\n\n")
                for module, data in results.items():
                    f.write(f"=== {module.upper()} RESULTS ===\n")
                    f.write(str(data) + "\n\n")
            print(f"[✓] Results saved to: {args.output}")
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()
