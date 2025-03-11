import requests
import re
from urllib.parse import urlparse
import os
import json
from datetime import datetime, timedelta

class DomainChecker:
    def __init__(self):
        self.cache_file = "domain_cache.json"
        self.cache_duration = timedelta(days=1)  # Cache results for 1 day
        self.cache = self._load_cache()
        
        # Sources for malicious domains
        self.blocklists = [
            "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            "https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt"
        ]
        
        # Load blocklists into memory
        self.blocked_domains = self._load_blocklists()
        
    def _load_cache(self):
        """Load domain reputation cache from file"""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    cache_data = json.load(f)
                    # Convert string timestamps to datetime objects
                    for domain, data in cache_data.items():
                        if 'timestamp' in data:
                            data['timestamp'] = datetime.fromisoformat(data['timestamp'])
                    return cache_data
            except Exception as e:
                print(f"Error loading cache: {e}")
        return {}
    
    def _save_cache(self):
        """Save domain reputation cache to file"""
        # Convert datetime objects to strings for JSON serialization
        serializable_cache = {}
        for domain, data in self.cache.items():
            serializable_cache[domain] = data.copy()
            if 'timestamp' in serializable_cache[domain]:
                serializable_cache[domain]['timestamp'] = data['timestamp'].isoformat()
                
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(serializable_cache, f)
        except Exception as e:
            print(f"Error saving cache: {e}")
        
    def _load_blocklists(self):
        """Load domain blocklists from sources"""
        domains = set()
        for url in self.blocklists:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    for line in response.text.splitlines():
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Extract domain from hosts file format or plain list
                            if line.startswith('0.0.0.0 ') or line.startswith('127.0.0.1 '):
                                domain = line.split()[1]
                            else:
                                domain = line
                            # Skip localhost entries
                            if domain not in ('localhost', 'localhost.localdomain', 'broadcasthost'):
                                domains.add(domain)
            except Exception as e:
                print(f"Error loading blocklist {url}: {e}")
        return domains
    
    def extract_urls(self, text):
        """Extract URLs from text"""
        # Basic URL regex
        url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
        return url_pattern.findall(text)
    
    def extract_domains(self, urls):
        """Extract domains from URLs"""
        domains = []
        for url in urls:
            try:
                # Add scheme if missing
                if not url.startswith(('http://', 'https://')):
                    url = 'http://' + url
                
                parsed = urlparse(url)
                if parsed.netloc:
                    domains.append(parsed.netloc)
            except Exception:
                continue
        return domains
    
    def check_domains(self, domains):
        """Check if domains are in blocklists or suspicious"""
        results = {}
        now = datetime.now()
        
        for domain in domains:
            # Check cache first
            if domain in self.cache:
                cache_entry = self.cache[domain]
                # Check if cache entry is still valid
                if now - cache_entry['timestamp'] < self.cache_duration:
                    results[domain] = cache_entry
                    continue
            
            # Check if domain is in blocklists
            in_blocklist = domain in self.blocked_domains
            
            # Check for common phishing indicators in domain
            suspicious_indicators = []
            
            # Check for lookalike domains (e.g., paypal-secure.com)
            common_brands = ['paypal', 'apple', 'microsoft', 'google', 'amazon', 'facebook', 
                            'netflix', 'twitter', 'instagram', 'bank', 'chase', 'wellsfargo', 
                            'bankofamerica', 'citibank', 'amex', 'americanexpress']
            
            for brand in common_brands:
                if brand in domain and not domain.endswith(f'.{brand}.com'):
                    suspicious_indicators.append(f"Contains brand name '{brand}'")
                    break
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.xyz', '.info', '.top', '.club', '.online', '.site']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                suspicious_indicators.append("Uses suspicious TLD")
            
            # Check for excessive subdomains
            if domain.count('.') > 3:
                suspicious_indicators.append("Excessive subdomains")
            
            # Check for character substitution (e.g., paypa1.com instead of paypal.com)
            if re.search(r'\d', domain):
                suspicious_indicators.append("Contains numbers in brand-like domain")
            
            # Calculate suspicion score (0-1)
            suspicion_score = 0.0
            
            if in_blocklist:
                suspicion_score = 1.0
            elif suspicious_indicators:
                # Base score for having indicators
                suspicion_score = 0.3
                # Add 0.1 for each indicator up to 0.9
                suspicion_score += min(len(suspicious_indicators) * 0.1, 0.6)
            
            # Store result
            result = {
                'domain': domain,
                'in_blocklist': in_blocklist,
                'suspicious_indicators': suspicious_indicators,
                'suspicion_score': suspicion_score,
                'timestamp': now
            }
            
            # Update cache
            self.cache[domain] = result
            results[domain] = result
        
        # Save updated cache
        self._save_cache()
        
        return results