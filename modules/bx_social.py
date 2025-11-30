import requests
from config.user_agents import get_random_agent

class BXSocial:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': get_random_agent()})
    
    def find_profiles(self, username):
        """Search for social media profiles"""
        print(f"[BX-SOCIAL] Searching profiles for: {username}")
        platforms = {
            'GitHub': f'https://github.com/{username}',
            'Twitter': f'https://twitter.com/{username}',
            'Instagram': f'https://instagram.com/{username}',
            'Facebook': f'https://facebook.com/{username}',
            'LinkedIn': f'https://linkedin.com/in/{username}',
            'YouTube': f'https://youtube.com/@{username}',
            'Reddit': f'https://reddit.com/user/{username}',
            'TikTok': f'https://tiktok.com/@{username}'
        }
        
        results = {}
        for platform, url in platforms.items():
            if self.check_profile_exists(url):
                results[platform] = url
                print(f"[+] Found {platform}: {url}")
                
        return results
    
    def check_profile_exists(self, url):
        """Check if social media profile exists"""
        try:
            response = self.session.head(url, timeout=10, allow_redirects=True)
            return response.status_code == 200
        except:
            return False