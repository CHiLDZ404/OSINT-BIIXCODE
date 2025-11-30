"""
BIIXCODE OSINT - Advanced Reconnaissance Module
Modul untuk reconnaissance lanjutan
"""

import requests
import re
import time
from bs4 import BeautifulSoup
from config.user_agents import get_random_agent
from config.api_keys import SECURITYTRAILS_API_KEY, SHODAN_API_KEY

class BXRecon:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': get_random_agent()})
    
    def comprehensive_scan(self, target):
        """Comprehensive reconnaissance scan"""
        print(f"[BX-RECON] Performing advanced recon on: {target}")
        results = {}
        
        try:
            # Determine target type
            target_type = self.determine_target_type(target)
            results['target_type'] = target_type
            
            if target_type == 'domain':
                # Domain-specific reconnaissance
                results['domain_recon'] = self.domain_reconnaissance(target)
                results['subdomain_scan'] = self.subdomain_discovery(target)
                results['technology_stack'] = self.technology_detection(target)
                results['directory_enum'] = self.directory_enumeration(target)
                
            elif target_type == 'ip':
                # IP-specific reconnaissance
                results['ip_recon'] = self.ip_reconnaissance(target)
                results['service_detection'] = self.service_detection(target)
                
            # General reconnaissance
            results['web_archives'] = self.check_web_archives(target)
            results['dorking_results'] = self.google_dorking(target)
            
        except Exception as e:
            print(f"[!] Reconnaissance error: {e}")
            
        return results
    
    def determine_target_type(self, target):
        """Determine if target is domain, IP, or email"""
        import re
        
        # IP address pattern
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        
        # Email pattern
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if re.match(ip_pattern, target):
            return 'ip'
        elif re.match(email_pattern, target):
            return 'email'
        else:
            return 'domain'
    
    def domain_reconnaissance(self, domain):
        """Advanced domain reconnaissance"""
        recon_data = {}
        
        try:
            # DNS Records Enumeration
            recon_data['dns_records'] = self.get_dns_records(domain)
            
            # Historical DNS Data
            recon_data['historical_dns'] = self.get_historical_dns(domain)
            
            # Certificate Transparency Logs
            recon_data['certificate_info'] = self.get_certificate_info(domain)
            
        except Exception as e:
            recon_data['error'] = str(e)
            
        return recon_data
    
    def get_dns_records(self, domain):
        """Get comprehensive DNS records"""
        import dns.resolver
        
        dns_records = {}
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                dns_records[record_type] = [str(rdata) for rdata in answers]
            except:
                dns_records[record_type] = []
                
        return dns_records
    
    def get_historical_dns(self, domain):
        """Get historical DNS data"""
        historical_data = {}
        
        # Using SecurityTrails if API key available
        if SECURITYTRAILS_API_KEY:
            try:
                headers = {'APIKEY': SECURITYTRAILS_API_KEY}
                response = self.session.get(
                    f'https://api.securitytrails.com/v1/history/{domain}/dns/a',
                    headers=headers,
                    timeout=10
                )
                if response.status_code == 200:
                    historical_data['securitytrails'] = response.json()
            except Exception as e:
                historical_data['securitytrails_error'] = str(e)
        
        return historical_data
    
    def get_certificate_info(self, domain):
        """Get SSL certificate information"""
        certificate_info = {}
        
        try:
            import ssl
            import socket
            
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    certificate_info['subject'] = dict(x[0] for x in cert['subject'])
                    certificate_info['issuer'] = dict(x[0] for x in cert['issuer'])
                    certificate_info['valid_from'] = cert['notBefore']
                    certificate_info['valid_until'] = cert['notAfter']
                    
        except Exception as e:
            certificate_info['error'] = str(e)
            
        return certificate_info
    
    def subdomain_discovery(self, domain):
        """Discover subdomains"""
        subdomains = []
        
        # Common subdomain list
        common_subs = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'cpanel', 'whm', 'autodiscover', 'autoconfig', 'admin', 'blog', 'shop',
            'api', 'app', 'dev', 'test', 'staging', 'cdn', 'static', 'media', 'forum'
        ]
        
        for sub in common_subs:
            test_domain = f"{sub}.{domain}"
            try:
                import dns.resolver
                dns.resolver.resolve(test_domain, 'A')
                subdomains.append(test_domain)
            except:
                continue
                
        return subdomains
    
    def technology_detection(self, domain):
        """Detect web technologies"""
        technologies = {}
        
        try:
            response = self.session.get(f"https://{domain}", timeout=10)
            
            # Server detection
            if 'server' in response.headers:
                technologies['server'] = response.headers['server']
            
            # Framework detection
            content = response.text.lower()
            
            # CMS Detection
            if 'wp-content' in content or 'wordpress' in content:
                technologies['cms'] = 'WordPress'
            elif 'joomla' in content:
                technologies['cms'] = 'Joomla'
            elif 'drupal' in content:
                technologies['cms'] = 'Drupal'
            
            # JavaScript frameworks
            if 'react' in content:
                technologies['frontend'] = 'React'
            elif 'angular' in content:
                technologies['frontend'] = 'Angular'
            elif 'vue' in content:
                technologies['frontend'] = 'Vue.js'
                
        except Exception as e:
            technologies['error'] = str(e)
            
        return technologies
    
    def directory_enumeration(self, domain):
        """Enumerate common directories"""
        directories = []
        common_dirs = [
            'admin', 'login', 'wp-admin', 'administrator', 'phpmyadmin',
            'cpanel', 'webmail', 'backup', 'uploads', 'images', 'css',
            'js', 'api', 'doc', 'docs', 'test', 'demo'
        ]
        
        for directory in common_dirs:
            url = f"https://{domain}/{directory}"
            try:
                response = self.session.head(url, timeout=5)
                if response.status_code == 200:
                    directories.append(url)
            except:
                continue
                
        return directories
    
    def ip_reconnaissance(self, ip):
        """IP-specific reconnaissance"""
        ip_recon = {}
        
        # Shodan data if available
        if SHODAN_API_KEY:
            try:
                response = self.session.get(
                    f'https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}',
                    timeout=10
                )
                if response.status_code == 200:
                    ip_recon['shodan'] = response.json()
            except Exception as e:
                ip_recon['shodan_error'] = str(e)
        
        return ip_recon
    
    def service_detection(self, ip):
        """Detect services running on IP"""
        services = {}
        common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
            995: 'POP3S', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL'
        }
        
        for port, service in common_ports.items():
            if self.check_port(ip, port):
                services[port] = service
                
        return services
    
    def check_port(self, ip, port):
        """Check if port is open"""
        import socket
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def check_web_archives(self, target):
        """Check web archives for historical data"""
        archives = {}
        
        try:
            # Wayback Machine
            wayback_url = f"http://web.archive.org/cdx/search/cdx?url={target}&output=json"
            response = self.session.get(wayback_url, timeout=10)
            if response.status_code == 200:
                archives['wayback'] = f"Found in Wayback Machine"
        except:
            pass
            
        return archives
    
    def google_dorking(self, target):
        """Perform basic Google dorking"""
        dorks = [
            f'site:{target}',
            f'inurl:{target}',
            f'intitle:{target}',
            f'filetype:pdf {target}'
        ]
        
        results = {}
        for dork in dorks:
            results[dork] = f"https://www.google.com/search?q={dork.replace(' ', '+')}"
            
        return results