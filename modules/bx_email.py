"""
BIIXCODE OSINT - Email Intelligence Module
Modul untuk investigasi alamat email
"""

import requests
import re
import dns.resolver
from config.user_agents import get_random_agent
from config.api_keys import HUNTER_API_KEY, HIBP_API_KEY, EMAILREP_API_KEY

class BXEmail:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': get_random_agent()})
    
    def analyze_email(self, email):
        """Comprehensive email analysis"""
        print(f"[BX-EMAIL] Analyzing email: {email}")
        results = {}
        
        try:
            # Email Validation
            results['validation'] = self.validate_email(email)
            
            # Email Reputation
            results['reputation'] = self.check_email_reputation(email)
            
            # Breach Check
            results['breaches'] = self.check_breaches(email)
            
            # Domain Information
            domain = email.split('@')[1]
            results['domain_info'] = self.get_domain_info(domain)
            
            # Social Media Search
            results['social_media'] = self.find_social_by_email(email)
            
            # Email Pattern Analysis
            results['pattern_analysis'] = self.analyze_email_pattern(email)
            
        except Exception as e:
            print(f"[!] Email analysis error: {e}")
            
        return results
    
    def validate_email(self, email):
        """Validate email format and check domain"""
        validation_result = {}
        
        # Basic format validation
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(pattern, email):
            validation_result['format'] = 'Valid'
        else:
            validation_result['format'] = 'Invalid'
            return validation_result
        
        # Domain validation
        domain = email.split('@')[1]
        try:
            dns.resolver.resolve(domain, 'MX')
            validation_result['domain_mx'] = 'Valid (MX records found)'
        except:
            validation_result['domain_mx'] = 'No MX records'
        
        return validation_result
    
    def check_email_reputation(self, email):
        """Check email reputation using various services"""
        reputation = {}
        
        # EmailRep API
        if EMAILREP_API_KEY:
            try:
                headers = {'Key': EMAILREP_API_KEY, 'User-Agent': 'BIIXCODE-OSINT'}
                response = self.session.get(f'https://emailrep.io/{email}', headers=headers, timeout=10)
                if response.status_code == 200:
                    reputation['emailrep'] = response.json()
            except Exception as e:
                reputation['emailrep_error'] = str(e)
        
        # Hunter.io Verification
        if HUNTER_API_KEY:
            try:
                response = self.session.get(
                    f'https://api.hunter.io/v2/email-verifier?email={email}&api_key={HUNTER_API_KEY}',
                    timeout=10
                )
                if response.status_code == 200:
                    reputation['hunter'] = response.json()
            except Exception as e:
                reputation['hunter_error'] = str(e)
        
        return reputation
    
    def check_breaches(self, email):
        """Check if email appears in data breaches"""
        breaches = {}
        
        # Have I Been Pwned
        if HIBP_API_KEY:
            try:
                headers = {'hibp-api-key': HIBP_API_KEY, 'User-Agent': 'BIIXCODE-OSINT'}
                response = self.session.get(
                    f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}',
                    headers=headers,
                    timeout=10
                )
                if response.status_code == 200:
                    breaches['hibp'] = response.json()
                elif response.status_code == 404:
                    breaches['hibp'] = 'No breaches found'
            except Exception as e:
                breaches['hibp_error'] = str(e)
        
        return breaches
    
    def get_domain_info(self, domain):
        """Get information about email domain"""
        domain_info = {}
        
        try:
            # Check if domain exists
            dns.resolver.resolve(domain, 'A')
            domain_info['exists'] = True
            
            # Get MX records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                domain_info['mx_records'] = [str(mx.exchange) for mx in mx_records]
            except:
                domain_info['mx_records'] = 'No MX records'
                
        except:
            domain_info['exists'] = False
            
        return domain_info
    
    def find_social_by_email(self, email):
        """Find social media profiles associated with email"""
        social_platforms = {}
        
        # Gravatar check
        import hashlib
        email_hash = hashlib.md5(email.lower().encode()).hexdigest()
        gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404&s=200"
        
        try:
            response = self.session.head(gravatar_url, timeout=5)
            if response.status_code == 200:
                social_platforms['gravatar'] = {
                    'url': gravatar_url,
                    'profile_url': f"https://gravatar.com/{email_hash}"
                }
        except:
            pass
            
        return social_platforms
    
    def analyze_email_pattern(self, email):
        """Analyze email pattern for intelligence"""
        analysis = {}
        username, domain = email.split('@')
        
        analysis['username'] = username
        analysis['domain'] = domain
        
        # Common pattern analysis
        if re.match(r'^[a-zA-Z]+\.[a-zA-Z]+$', username):
            analysis['pattern'] = 'firstname.lastname'
        elif re.match(r'^[a-zA-Z]+[0-9]+$', username):
            analysis['pattern'] = 'name_with_numbers'
        elif len(username) <= 3:
            analysis['pattern'] = 'short_username'
        else:
            analysis['pattern'] = 'unknown_pattern'
            
        return analysis