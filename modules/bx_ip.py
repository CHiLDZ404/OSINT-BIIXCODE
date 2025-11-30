"""
BIIXCODE OSINT - IP Intelligence Module
Modul untuk investigasi alamat IP
"""

import requests
import socket
import json
from config.user_agents import get_random_agent
from config.api_keys import SHODAN_API_KEY, VIRUSTOTAL_API_KEY, GREYNOISE_API_KEY, OTX_API_KEY

class BXIP:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': get_random_agent()})
    
    def investigate(self, ip):
        """Comprehensive IP investigation"""
        print(f"[BX-IP] Investigating IP: {ip}")
        results = {}
        
        try:
            # Basic IP Information
            results['basic_info'] = self.get_basic_info(ip)
            
            # Geolocation
            results['geolocation'] = self.get_geolocation(ip)
            
            # Threat Intelligence
            results['threat_intel'] = self.get_threat_intelligence(ip)
            
            # Port Scanning (Basic)
            results['open_ports'] = self.quick_port_scan(ip)
            
            # Network Information
            results['network_info'] = self.get_network_info(ip)
            
            # Associated Domains
            results['associated_domains'] = self.find_associated_domains(ip)
            
        except Exception as e:
            print(f"[!] IP investigation error: {e}")
            
        return results
    
    def get_basic_info(self, ip):
        """Get basic IP information"""
        basic_info = {}
        
        try:
            # Validate IP format
            socket.inet_aton(ip)
            basic_info['valid'] = True
            
            # IP Type
            if ip.startswith('10.') or ip.startswith('192.168.') or (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31):
                basic_info['type'] = 'Private'
            else:
                basic_info['type'] = 'Public'
                
            # Reverse DNS
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                basic_info['reverse_dns'] = hostname
            except:
                basic_info['reverse_dns'] = 'Not available'
                
        except socket.error:
            basic_info['valid'] = False
            
        return basic_info
    
    def get_geolocation(self, ip):
        """Get IP geolocation information"""
        geolocation = {}
        
        try:
            # Using ipapi.co
            response = self.session.get(f'http://ipapi.co/{ip}/json/', timeout=10)
            if response.status_code == 200:
                data = response.json()
                geolocation['ipapi'] = {
                    'country': data.get('country_name'),
                    'city': data.get('city'),
                    'region': data.get('region'),
                    'isp': data.get('org'),
                    'timezone': data.get('timezone'),
                    'coordinates': f"{data.get('latitude')}, {data.get('longitude')}"
                }
        except Exception as e:
            geolocation['ipapi_error'] = str(e)
            
        return geolocation
    
    def get_threat_intelligence(self, ip):
        """Get threat intelligence from various sources"""
        threat_intel = {}
        
        # VirusTotal
        if VIRUSTOTAL_API_KEY:
            try:
                headers = {'x-apikey': VIRUSTOTAL_API_KEY}
                response = self.session.get(
                    f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                    headers=headers,
                    timeout=10
                )
                if response.status_code == 200:
                    threat_intel['virustotal'] = response.json()
            except Exception as e:
                threat_intel['virustotal_error'] = str(e)
        
        # Shodan
        if SHODAN_API_KEY:
            try:
                response = self.session.get(
                    f'https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}',
                    timeout=10
                )
                if response.status_code == 200:
                    threat_intel['shodan'] = response.json()
            except Exception as e:
                threat_intel['shodan_error'] = str(e)
        
        # GreyNoise
        if GREYNOISE_API_KEY:
            try:
                headers = {'key': GREYNOISE_API_KEY, 'User-Agent': 'BIIXCODE-OSINT'}
                response = self.session.get(
                    f'https://api.greynoise.io/v3/community/{ip}',
                    headers=headers,
                    timeout=10
                )
                if response.status_code == 200:
                    threat_intel['greynoise'] = response.json()
            except Exception as e:
                threat_intel['greynoise_error'] = str(e)
        
        # AlienVault OTX
        if OTX_API_KEY:
            try:
                headers = {'X-OTX-API-KEY': OTX_API_KEY}
                response = self.session.get(
                    f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general',
                    headers=headers,
                    timeout=10
                )
                if response.status_code == 200:
                    threat_intel['otx'] = response.json()
            except Exception as e:
                threat_intel['otx_error'] = str(e)
        
        return threat_intel
    
    def quick_port_scan(self, ip):
        """Quick port scan for common ports"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 8080, 8443]
        open_ports = []
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
                
        return open_ports
    
    def get_network_info(self, ip):
        """Get network information for IP"""
        network_info = {}
        
        try:
            # Get ASN information using ipapi
            response = self.session.get(f'http://ipapi.co/{ip}/json/', timeout=10)
            if response.status_code == 200:
                data = response.json()
                network_info['asn'] = data.get('asn')
                network_info['org'] = data.get('org')
                network_info['network'] = data.get('network')
        except:
            pass
            
        return network_info
    
    def find_associated_domains(self, ip):
        """Find domains associated with IP"""
        domains = []
        
        # This is a basic implementation
        # In practice, you'd use services like SecurityTrails or similar
        try:
            # Reverse DNS already gives one domain
            hostname = socket.gethostbyaddr(ip)[0]
            if hostname and hostname != ip:
                domains.append(hostname)
        except:
            pass
            
        return domains
