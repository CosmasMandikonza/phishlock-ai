"""
PhishLock AI URL Extractor and Analyzer
Advanced URL analysis for phishing detection
"""

import re
import tldextract
import urllib.parse
import difflib
import ipaddress
import socket
from typing import List, Dict, Any, Tuple, Optional
import requests
from urllib.parse import urlparse

class URLExtractor:
    def __init__(self):
        """Initialize the URL extractor and analyzer."""
        # Regex patterns for URL extraction
        self.url_patterns = [
            # Standard URLs
            re.compile(r'https?://[^\s/$.?#].[^\s]*', re.IGNORECASE),
            # URLs without scheme (www.example.com)
            re.compile(r'www\.[^\s/$.?#].[^\s]*', re.IGNORECASE),
            # Common obfuscation with brackets or parentheses
            re.compile(r'https?://(?:\(|\[|\{)([^\s\(\)\[\]\{\}]+)(?:\)|\]|\})', re.IGNORECASE),
            # Shortened domain patterns
            re.compile(r'(bit\.ly|tinyurl\.com|goo\.gl|t\.co|is\.gd)/[a-zA-Z0-9]+', re.IGNORECASE),
            # IP addresses with scheme
            re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[^\s]*', re.IGNORECASE),
            # Raw IP addresses with path
            re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?/[^\s]*', re.IGNORECASE)
        ]
        
        # Common legitimate domains
        self.common_legitimate_domains = [
            "google.com", "microsoft.com", "apple.com", "amazon.com", "facebook.com",
            "twitter.com", "linkedin.com", "instagram.com", "youtube.com", "yahoo.com",
            "paypal.com", "netflix.com", "dropbox.com", "github.com", "adobe.com",
            "wordpress.com", "spotify.com", "slack.com", "zoom.us", "salesforce.com",
            "ibm.com", "oracle.com", "cisco.com", "intel.com", "hp.com", "dell.com",
            "amd.com", "nvidia.com", "samsung.com", "sony.com", "lg.com", "verizon.com",
            "att.com", "t-mobile.com", "comcast.com", "xfinity.com", "spectrum.com"
        ]
        
        # List of suspicious TLDs often used in phishing
        self.suspicious_tlds = [
            "xyz", "top", "club", "online", "site", "fun", "space", "info", "stream",
            "gq", "cf", "ga", "ml", "tk", "pw", "su", "rocks", "racing", "icu", "work", 
            "casa", "loan", "date", "faith", "review", "science", "trade", "webcam", "bid"
        ]
        
        # URL shortening services
        self.url_shorteners = [
            "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "cli.gs", "pic.gd", "go2l.ink",
            "shorten.link", "buff.ly", "rebrand.ly", "tiny.cc", "ow.ly", "snip.ly", "url.is",
            "cutt.ly", "short.io", "shorturl.at", "s.id", "v.gd", "gl.am", "adf.ly"
        ]
        
    def extract_urls(self, text: str) -> List[str]:
        """
        Extract URLs from text using multiple regex patterns.
        
        Args:
            text: Text to extract URLs from
            
        Returns:
            List of extracted URLs
        """
        urls = []
        
        # Apply each regex pattern
        for pattern in self.url_patterns:
            found_urls = pattern.findall(text)
            
            # Handle the matches based on pattern type
            if isinstance(found_urls, list):
                if found_urls and isinstance(found_urls[0], tuple):
                    # Extract from groups if needed
                    for match in found_urls:
                        if match:
                            urls.append(match[0] if isinstance(match, tuple) else match)
                else:
                    urls.extend(found_urls)
        
        # Normalize URLs
        normalized_urls = []
        for url in urls:
            # Add scheme if missing
            if not url.startswith(('http://', 'https://')):
                if url.startswith('www.'):
                    url = 'http://' + url
                elif re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                    url = 'http://' + url
            
            # Check if it's a valid URL
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    normalized_urls.append(url)
            except Exception:
                continue
        
        # Remove duplicates while preserving order
        unique_urls = []
        seen = set()
        for url in normalized_urls:
            if url not in seen:
                unique_urls.append(url)
                seen.add(url)
        
        return unique_urls
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze a URL for phishing indicators.
        
        Args:
            url: URL to analyze
            
        Returns:
            Dictionary with analysis results
        """
        # Parse URL
        try:
            parsed_url = urlparse(url)
            
            # Add scheme if missing
            if not parsed_url.scheme:
                url = 'http://' + url
                parsed_url = urlparse(url)
                
            # Extract domain parts
            tld_parts = tldextract.extract(url)
            domain = tld_parts.domain
            suffix = tld_parts.suffix
            subdomain = tld_parts.subdomain
            full_domain = f"{tld_parts.domain}.{tld_parts.suffix}"
            
            # Initialize results
            result = {
                'url': url,
                'domain': full_domain,
                'subdomain': subdomain,
                'tld': suffix,
                'suspicious_indicators': [],
                'score': 0.0,
                'is_shortened': False,
                'is_ip_address': False,
                'is_suspicious': False,
                'suspicious_level': 'safe'
            }
            
            # Check for IP address
            is_ip_address = False
            try:
                ipaddress.ip_address(parsed_url.netloc)
                is_ip_address = True
            except ValueError:
                try:
                    # Handle port numbers
                    host = parsed_url.netloc.split(':')[0]
                    ipaddress.ip_address(host)
                    is_ip_address = True
                except ValueError:
                    pass
            
            if is_ip_address:
                result['is_ip_address'] = True
                result['suspicious_indicators'].append('Uses IP address instead of domain name')
                result['score'] += 0.3
            
            # Check for URL shorteners
            if any(shortener in full_domain.lower() for shortener in self.url_shorteners):
                result['is_shortened'] = True
                result['suspicious_indicators'].append('Uses URL shortening service')
                result['score'] += 0.2
            
            # Check for suspicious TLDs
            if suffix.lower() in self.suspicious_tlds:
                result['suspicious_indicators'].append(f'Uses suspicious TLD (.{suffix})')
                result['score'] += 0.25
            
            # Check for excessive subdomains
            if subdomain and subdomain.count('.') > 2:
                result['suspicious_indicators'].append('Excessive subdomains')
                result['score'] += 0.2
            
            # Check for brand impersonation in domain
            common_brands = ["paypal", "microsoft", "apple", "google", "amazon", "facebook", 
                           "netflix", "twitter", "instagram", "bank", "chase", "wellsfargo", 
                           "bankofamerica", "citibank", "amex", "americanexpress"]
            
            # Check for brand name in domain but not matching legitimate domain
            brand_impersonation = False
            impersonated_brand = None
            
            for brand in common_brands:
                # Check if brand appears in domain
                if brand.lower() in domain.lower():
                    is_legitimate = False
                    
                    # Compare with legitimate domains
                    for legit_domain in self.common_legitimate_domains:
                        if brand.lower() in legit_domain.lower() and domain.lower() in legit_domain.lower():
                            is_legitimate = True
                            break
                    
                    if not is_legitimate:
                        brand_impersonation = True
                        impersonated_brand = brand
                        break
            
            if brand_impersonation:
                result['suspicious_indicators'].append(f'Potential {impersonated_brand} impersonation')
                result['score'] += 0.35
            
            # Check for misleading domains (typosquatting)
            for legit_domain in self.common_legitimate_domains:
                # Check how similar our domain is to the legitimate domain
                similarity = difflib.SequenceMatcher(None, full_domain.lower(), legit_domain.lower()).ratio()
                
                # High similarity but not exact match indicates possible typosquatting
                if 0.7 < similarity < 0.99:
                    result['suspicious_indicators'].append(f'Appears to mimic {legit_domain}')
                    result['score'] += 0.3
                    break
            
            # Check for numbers replacing letters (e.g., paypa1.com instead of paypal.com)
            if re.search(r'\d', domain):
                # Only suspicious if combined with a brand-like name
                if any(brand.lower() in domain.lower() for brand in common_brands):
                    result['suspicious_indicators'].append('Uses numbers to replace letters in brand name')
                    result['score'] += 0.25
            
            # Check for unusual URL patterns
            if any(char in parsed_url.netloc for char in ['@', '-', '_']):
                result['suspicious_indicators'].append('Contains unusual characters in domain')
                result['score'] += 0.15
            
            # Check for misleading path
            misleading_path_patterns = [
                r'/login', r'/signin', r'/account', r'/secure', r'/verify',
                r'/authenticate', r'/webscr', r'/update', r'/confirm'
            ]
            
            if parsed_url.path:
                for pattern in misleading_path_patterns:
                    if re.search(pattern, parsed_url.path, re.IGNORECASE):
                        # Check if path contains brand name but domain doesn't match
                        for brand in common_brands:
                            if brand.lower() in parsed_url.path.lower() and brand.lower() not in full_domain.lower():
                                result['suspicious_indicators'].append(f'Path suggests {brand} but domain does not match')
                                result['score'] += 0.25
                                break
            
            # Check for data URLs
            if parsed_url.scheme == 'data':
                result['suspicious_indicators'].append('Uses data URL scheme')
                result['score'] += 0.4
            
            # Determine suspicious level
            if result['score'] >= 0.7:
                result['is_suspicious'] = True
                result['suspicious_level'] = 'high'
            elif result['score'] >= 0.4:
                result['is_suspicious'] = True
                result['suspicious_level'] = 'medium'
            elif result['score'] >= 0.2:
                result['suspicious_level'] = 'low'
            
            return result
        
        except Exception as e:
            print(f"Error analyzing URL {url}: {e}")
            return {
                'url': url,
                'error': str(e),
                'score': 0.0,
                'is_suspicious': False,
                'suspicious_level': 'unknown'
            }
    
    def analyze_urls(self, urls: List[str]) -> List[Dict[str, Any]]:
        """
        Analyze multiple URLs.
        
        Args:
            urls: List of URLs to analyze
            
        Returns:
            List of analysis results for each URL
        """
        results = []
        for url in urls:
            result = self.analyze_url(url)
            results.append(result)
        return results
    
    def resolve_shortened_url(self, url: str) -> Optional[str]:
        """
        Attempt to resolve a shortened URL to its destination.
        
        Args:
            url: Shortened URL
            
        Returns:
            Full destination URL or None if unsuccessful
        """
        try:
            response = requests.head(url, allow_redirects=True, timeout=5)
            return response.url
        except Exception as e:
            print(f"Error resolving shortened URL {url}: {e}")
            return None
    
    def analyze_urls_in_text(self, text: str) -> Dict[str, Any]:
        """
        Extract and analyze all URLs in a text.
        
        Args:
            text: Text to extract and analyze URLs from
            
        Returns:
            Analysis results including all URLs and their analysis
        """
        # Extract URLs
        urls = self.extract_urls(text)
        
        # Analyze each URL
        url_analyses = self.analyze_urls(urls)
        
        # Calculate overall suspicion score
        suspicious_count = sum(1 for result in url_analyses if result.get('is_suspicious', False))
        overall_score = 0.0
        
        if urls:
            # Average score of all URLs
            overall_score = sum(result.get('score', 0.0) for result in url_analyses) / len(urls)
            
            # Increase weight if there are multiple suspicious URLs
            if suspicious_count > 1:
                overall_score = min(1.0, overall_score * (1.0 + (suspicious_count * 0.1)))
        
        # Determine if any shortened URLs should be resolved
        shortened_urls = [
            result for result in url_analyses 
            if result.get('is_shortened', False) and not result.get('error', False)
        ]
        
        # Resolve shortened URLs (limit to 3 to avoid excessive requests)
        resolved_urls = []
        for result in shortened_urls[:3]:
            resolved_url = self.resolve_shortened_url(result['url'])
            if resolved_url and resolved_url != result['url']:
                resolved_urls.append({
                    'original_url': result['url'],
                    'resolved_url': resolved_url,
                    'analysis': self.analyze_url(resolved_url)
                })
        
        return {
            'urls_found': urls,
            'url_count': len(urls),
            'analyses': url_analyses,
            'suspicious_count': suspicious_count,
            'overall_score': overall_score,
            'overall_suspicious': overall_score > 0.4,
            'resolved_shortened_urls': resolved_urls
        }