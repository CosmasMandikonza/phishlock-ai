"""
PhishLock AI Logo Detector
Detects brand logos in HTML content to identify brand impersonation
"""

import re
from typing import Dict, List, Any, Optional, Tuple
from bs4 import BeautifulSoup
import requests
import hashlib
from urllib.parse import urljoin, urlparse
import os

class LogoDetector:
    def __init__(self):
        """Initialize the logo detector."""
        # Dictionary of brand logo fingerprints (simplified for implementation)
        # In a real implementation, this would use computer vision techniques
        self.brand_logos = {
            "microsoft": {
                "patterns": [
                    r'(microsoft|ms).*\.(png|jpg|svg|gif)',
                    r'(ms-logo|microsoft-logo|msft).*\.(png|jpg|svg|gif)'
                ],
                "keywords": ["microsoft", "windows", "office", "microsoft 365", "outlook", "azure", "msft"],
                "colors": ["#F25022", "#7FBA00", "#00A4EF", "#FFB900"]  # Microsoft square colors
            },
            "apple": {
                "patterns": [
                    r'apple.*\.(png|jpg|svg|gif)',
                    r'(iphone|ipad|mac|ios).*logo.*\.(png|jpg|svg|gif)'
                ],
                "keywords": ["apple", "iphone", "ipad", "mac", "ios", "macos", "watchos", "apple id"],
                "colors": ["#A3AAAE", "#000000", "#F9F6EF"]  # Apple logo colors
            },
            "google": {
                "patterns": [
                    r'google.*\.(png|jpg|svg|gif)',
                    r'(gmail|gsuite|g-suite).*logo.*\.(png|jpg|svg|gif)'
                ],
                "keywords": ["google", "gmail", "gsuite", "google drive", "google docs", "android"],
                "colors": ["#4285F4", "#34A853", "#FBBC05", "#EA4335"]  # Google logo colors
            },
            "amazon": {
                "patterns": [
                    r'amazon.*\.(png|jpg|svg|gif)',
                    r'(amazon|aws|prime).*logo.*\.(png|jpg|svg|gif)'
                ],
                "keywords": ["amazon", "aws", "prime", "amazon web services", "alexa"],
                "colors": ["#FF9900", "#146EB4", "#232F3E"]  # Amazon colors
            },
            "paypal": {
                "patterns": [
                    r'paypal.*\.(png|jpg|svg|gif)',
                    r'(paypal|pay-pal).*logo.*\.(png|jpg|svg|gif)'
                ],
                "keywords": ["paypal", "payment", "pay pal", "pay-pal"],
                "colors": ["#003087", "#009CDE", "#012169"]  # PayPal colors
            },
            "facebook": {
                "patterns": [
                    r'(facebook|fb).*\.(png|jpg|svg|gif)',
                    r'(facebook|fb).*logo.*\.(png|jpg|svg|gif)'
                ],
                "keywords": ["facebook", "fb", "meta", "social media"],
                "colors": ["#3b5998", "#4267B2", "#898F9C"]  # Facebook colors
            },
            "netflix": {
                "patterns": [
                    r'netflix.*\.(png|jpg|svg|gif)',
                    r'netflix.*logo.*\.(png|jpg|svg|gif)'
                ],
                "keywords": ["netflix", "streaming", "movies", "tv shows"],
                "colors": ["#E50914", "#221F1F", "#F5F5F1"]  # Netflix colors
            },
            "bank": {
                "patterns": [
                    r'(bank|banking|chase|wellsfargo|citi|hsbc|barclays).*\.(png|jpg|svg|gif)',
                    r'(bank|banking|financial).*logo.*\.(png|jpg|svg|gif)'
                ],
                "keywords": ["bank", "banking", "chase", "wells fargo", "citi", "hsbc", "barclays", "account"],
                "colors": []  # Generic, varies by bank
            }
        }
        
        # Cache directory for downloaded images
        self.cache_dir = "data/logo_cache"
        os.makedirs(self.cache_dir, exist_ok=True)
        
    def extract_images_from_html(self, html_content: str, base_url: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Extract image information from HTML content.
        
        Args:
            html_content: HTML content to parse
            base_url: Base URL for resolving relative URLs
            
        Returns:
            List of image information dictionaries
        """
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            images = []
            
            # Extract all image tags
            for img in soup.find_all('img'):
                src = img.get('src', '')
                alt = img.get('alt', '')
                width = img.get('width', '')
                height = img.get('height', '')
                
                # Skip very small or empty images
                if not src or (width and height and int(width) < 20 and int(height) < 20):
                    continue
                
                # Resolve relative URLs if base_url is provided
                if base_url and not src.startswith(('http://', 'https://', 'data:')):
                    src = urljoin(base_url, src)
                
                images.append({
                    'src': src,
                    'alt': alt,
                    'width': width,
                    'height': height
                })
            
            # Also check for background images in CSS
            for elem in soup.find_all(style=True):
                style = elem.get('style', '')
                background_urls = re.findall(r'background(-image)?:\s*url\([\'"]?([^\'"]*)[\'"]?\)', style)
                
                for _, url in background_urls:
                    if url:
                        # Resolve relative URLs
                        if base_url and not url.startswith(('http://', 'https://', 'data:')):
                            url = urljoin(base_url, url)
                        
                        images.append({
                            'src': url,
                            'alt': '',
                            'width': '',
                            'height': '',
                            'type': 'background'
                        })
            
            return images
            
        except Exception as e:
            print(f"Error extracting images from HTML: {e}")
            return []
    
    def analyze_image_urls(self, image_urls: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze image URLs for brand logos.
        
        Args:
            image_urls: List of image information dictionaries
            
        Returns:
            Analysis results
        """
        results = {
            'detected_brands': {},
            'total_images': len(image_urls),
            'brand_images': 0,
            'strongest_brand_match': None,
            'strongest_match_score': 0.0
        }
        
        for brand, brand_info in self.brand_logos.items():
            brand_matches = []
            
            for img in image_urls:
                score = 0.0
                match_reason = []
                
                src = img.get('src', '')
                alt = img.get('alt', '').lower()
                
                # Check if image filename matches brand patterns
                for pattern in brand_info['patterns']:
                    if re.search(pattern, src, re.IGNORECASE):
                        score += 0.4
                        match_reason.append(f"Filename matches {brand} pattern")
                        break
                
                # Check if alt text contains brand keywords
                for keyword in brand_info['keywords']:
                    if keyword.lower() in alt:
                        score += 0.3
                        match_reason.append(f"Alt text contains {keyword}")
                        break
                
                # For a real implementation, here we would download and analyze the image content
                # For now, we just use the patterns and keywords
                
                if score > 0.3:
                    brand_matches.append({
                        'image': img,
                        'score': score,
                        'reasons': match_reason
                    })
            
            if brand_matches:
                # Get highest scoring match
                best_match = max(brand_matches, key=lambda x: x['score'])
                
                results['detected_brands'][brand] = {
                    'matches': brand_matches,
                    'match_count': len(brand_matches),
                    'best_match': best_match
                }
                
                # Update strongest brand match
                if best_match['score'] > results['strongest_match_score']:
                    results['strongest_match_score'] = best_match['score']
                    results['strongest_brand_match'] = brand
        
        # Count total brand images
        results['brand_images'] = sum(len(info['matches']) for info in results['detected_brands'].values())
        
        return results
    
    def analyze_html_for_brand_logos(self, html_content: str, url: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze HTML content for brand logos.
        
        Args:
            html_content: HTML content to analyze
            url: URL of the HTML content for resolving relative URLs
            
        Returns:
            Analysis results
        """
        # Extract images from HTML
        images = self.extract_images_from_html(html_content, url)
        
        # Analyze images for brand logos
        logo_analysis = self.analyze_image_urls(images)
        
        # Extract domain from URL if provided
        domain = None
        if url:
            try:
                parsed_url = urlparse(url)
                domain = parsed_url.netloc
            except Exception:
                pass
        
        # Add impersonation detection
        impersonation_detected = False
        impersonated_brand = None
        impersonation_confidence = 0.0
        
        if logo_analysis['strongest_brand_match'] and domain:
            brand = logo_analysis['strongest_brand_match']
            brand_info = self.brand_logos[brand]
            
            # Check if domain contains brand name or keywords
            if not any(keyword.lower() in domain.lower() for keyword in brand_info['keywords']):
                impersonation_detected = True
                impersonated_brand = brand
                impersonation_confidence = logo_analysis['strongest_match_score']
        
        # Return comprehensive results
        return {
            'images': images,
            'logo_analysis': logo_analysis,
            'impersonation_detected': impersonation_detected,
            'impersonated_brand': impersonated_brand,
            'impersonation_confidence': impersonation_confidence,
            'domain': domain
        }