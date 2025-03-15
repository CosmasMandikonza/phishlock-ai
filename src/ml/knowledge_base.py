"""
Knowledge Base for PhishLock AI
Manages a database of known phishing patterns, legitimate brand templates, 
and phishing tactics
"""
import os
import json
import requests
from datetime import datetime, timedelta

class KnowledgeBase:
    def __init__(self, knowledge_base_path="knowledge_base.json"):
        """
        Initialize the knowledge base.
        
        Args:
            knowledge_base_path: Path to the knowledge base JSON file
        """
        self.knowledge_base_path = knowledge_base_path
        self.last_update = None
        self.update_interval = timedelta(days=1)  # Update once a day
        
        # Load or initialize the knowledge base
        if os.path.exists(knowledge_base_path):
            with open(knowledge_base_path, 'r') as f:
                self.data = json.load(f)
                if 'last_update' in self.data:
                    self.last_update = datetime.fromisoformat(self.data['last_update'])
        else:
            self.data = self._initialize_knowledge_base()
            self._save_knowledge_base()
        
        # Check if update is needed
        self._check_update()
    
    def _initialize_knowledge_base(self):
        """Initialize a new knowledge base with basic data"""
        return {
            "version": "1.0",
            "last_update": datetime.now().isoformat(),
            "brands": {
                "Microsoft": {
                    "domains": ["microsoft.com", "office.com", "outlook.com", "live.com"],
                    "indicators": ["Microsoft 365", "Office 365", "Azure", "Outlook"],
                    "templates": [
                        "Your Microsoft account password will expire today. To ensure that your account is not interrupted, please update your password now.",
                        "Your Microsoft 365 subscription is about to expire. Please renew now to avoid service interruption."
                    ]
                },
                "PayPal": {
                    "domains": ["paypal.com", "paypal.co.uk"],
                    "indicators": ["PayPal account", "transaction", "payment"],
                    "templates": [
                        "We noticed some unusual activity in your PayPal account. Please verify your information to secure your account.",
                        "Your PayPal account has been limited until we hear from you. Please login to resolve the issue."
                    ]
                },
                "Amazon": {
                    "domains": ["amazon.com", "amazon.co.uk", "amazon.ca", "amazonaws.com"],
                    "indicators": ["Amazon order", "Amazon Prime", "delivery"],
                    "templates": [
                        "There is a problem with your Amazon order. Please update your payment information to avoid order cancellation.",
                        "Your Amazon Prime membership will automatically renew. To verify your billing information, please sign in to your account."
                    ]
                },
                "Apple": {
                    "domains": ["apple.com", "icloud.com"],
                    "indicators": ["Apple ID", "iCloud", "iTunes"],
                    "templates": [
                        "Your Apple ID was used to sign in to iCloud on a new device. If this wasn't you, please verify your account now.",
                        "Your Apple ID has been locked for security reasons. Please verify your account information to unlock it."
                    ]
                },
                "Google": {
                    "domains": ["google.com", "gmail.com", "googlemail.com"],
                    "indicators": ["Google account", "Gmail", "YouTube"],
                    "templates": [
                        "A sign-in attempt requires further verification because we did not recognize your device. To continue, please verify your identity.",
                        "Your Google Account was just signed in from a new device. If this was you, you can ignore this email. If not, please secure your account."
                    ]
                },
                "Bank of America": {
                    "domains": ["bankofamerica.com", "bofa.com"],
                    "indicators": ["Bank of America account", "checking account", "savings account"],
                    "templates": [
                        "We've temporarily limited your access to Bank of America Online Banking. Please verify your information to restore access.",
                        "Important notice regarding your Bank of America account. Please review and verify your information."
                    ]
                },
                "Chase": {
                    "domains": ["chase.com"],
                    "indicators": ["Chase account", "Chase Bank", "Chase credit card"],
                    "templates": [
                        "Your Chase account has been locked due to too many invalid login attempts. Please verify your identity to unlock your account.",
                        "We detected unusual activity on your Chase credit card. Please verify recent transactions to prevent fraud."
                    ]
                },
                "Wells Fargo": {
                    "domains": ["wellsfargo.com"],
                    "indicators": ["Wells Fargo account", "Wells Fargo Bank"],
                    "templates": [
                        "Your Wells Fargo account has been temporarily suspended. Please update your information to regain access.",
                        "Wells Fargo: We've noticed unusual activity in your account. Please verify your identity to prevent unauthorized access."
                    ]
                }
            },
            "tactics": {
                "urgency": [
                    r"\b(urgent|immediately|asap|right away|promptly|time-sensitive)\b",
                    r"\b(act now|expir(e|es|ed|ing)|within \d+ (hour|day|minute)s?)\b",
                    r"\b(limited time|running out|last chance|deadline)\b"
                ],
                "fear": [
                    r"\b(suspicious|unauthorized|unusual) (activity|access|login|sign-in|transaction)\b",
                    r"\b(security (issue|problem|concern|violation|breach|incident|alert|warning))\b",
                    r"\b(account (suspended|disabled|restricted|locked|blocked|limited))\b",
                    r"\b(fraud|fraudulent|suspicious)\b"
                ],
                "reward": [
                    r"\b(congratulations|won|winner|prize|reward|gift)\b",
                    r"\b(free|discount|offer|special|promotion|deal)\b",
                    r"\b(limited offer|exclusive)\b"
                ],
                "curiosity": [
                    r"\b(check out|look at|view|see|discover)\b",
                    r"\b(breaking news|important update|critical information)\b"
                ],
                "authority": [
                    r"\b(official|important|alert|warning|notice|notification)\b",
                    r"\b(administration|administrator|system)\b",
                    r"from the desk of",
                    r"on behalf of"
                ],
                "generic_greeting": [
                    r"^(dear customer|dear user|dear client|dear member|valued customer)",
                    r"\b(hi there|hello there)\b"
                ],
                "request_for_information": [
                    r"\b(verify|confirm|validate|update) (your|account|personal|payment|billing|credit card) (information|details|data)\b",
                    r"\b(provide|send|enter|input) (your|account|personal|payment|billing|credit card) (information|details|data)\b",
                    r"\b(username|password|login|credentials|ssn|social security|credit card|card number)\b"
                ]
            },
            "indicators": {
                "suspicious_domains": [
                    r"([a-zA-Z0-9-]+\.(top|xyz|club|online|site|icu|space|fun|live|click))",
                    r"(microsoft|paypal|amazon|apple|google)-[a-zA-Z0-9]+\.[a-zA-Z0-9-]+",
                    r"(secure|signin|login|auth|verify|account|billing)[-]?[a-zA-Z0-9]*\.[a-zA-Z0-9-]+"
                ],
                "mixed_character_sets": [
                    r"([a-zA-Z0-9]*[а-яА-Я]+[a-zA-Z0-9]*\.[a-zA-Z]+)",  # Cyrillic mixed with Latin
                    r"([a-zA-Z0-9]*\d+[a-zA-Z]+\d+[a-zA-Z0-9]*\.[a-zA-Z]+)"  # Numbers mixed with letters
                ],
                "suspicious_url_paths": [
                    r"(\/secure\/|\/signin\/|\/login\/|\/verify\/|\/auth\/|\/account\/update\/)",
                    r"(\/password\/reset\/|\/confirm\/|\/validate\/)"
                ]
            }
        }
    
    def _save_knowledge_base(self):
        """Save the knowledge base to disk"""
        with open(self.knowledge_base_path, 'w') as f:
            json.dump(self.data, f, indent=2)
    
    def _check_update(self):
        """Check if the knowledge base needs updating"""
        now = datetime.now()
        if not self.last_update or (now - self.last_update) > self.update_interval:
            self._update_knowledge_base()
    
    def _update_knowledge_base(self):
        """
        Update the knowledge base with new information.
        This could connect to a remote database, API, or other source.
        """
        # In a real implementation, you might fetch updates from a central repository
        # For now, we'll just update the timestamp
        self.data['last_update'] = datetime.now().isoformat()
        self.last_update = datetime.now()
        self._save_knowledge_base()
        
        # Example of how you might update from an online source
        # self._fetch_updates_from_api()
    
    def _fetch_updates_from_api(self):
        """Fetch updates from a hypothetical API"""
        try:
            # This would be replaced with a real API endpoint
            api_url = "https://api.phishlock.example/knowledge_base/latest"
            
            # Make the request
            response = requests.get(api_url)
            
            if response.status_code == 200:
                updates = response.json()
                
                # Merge updates with existing data
                if 'brands' in updates:
                    for brand, data in updates['brands'].items():
                        if brand in self.data['brands']:
                            # Update existing brand data
                            self.data['brands'][brand].update(data)
                        else:
                            # Add new brand
                            self.data['brands'][brand] = data
                
                # Update tactics
                if 'tactics' in updates:
                    for tactic, patterns in updates['tactics'].items():
                        if tactic in self.data['tactics']:
                            # Merge patterns, avoiding duplicates
                            self.data['tactics'][tactic] = list(set(self.data['tactics'][tactic] + patterns))
                        else:
                            # Add new tactic
                            self.data['tactics'][tactic] = patterns
                
                # Update indicators
                if 'indicators' in updates:
                    for indicator, patterns in updates['indicators'].items():
                        if indicator in self.data['indicators']:
                            # Merge patterns, avoiding duplicates
                            self.data['indicators'][indicator] = list(set(self.data['indicators'][indicator] + patterns))
                        else:
                            # Add new indicator
                            self.data['indicators'][indicator] = patterns
                
                # Save updates
                self._save_knowledge_base()
                
        except Exception as e:
            print(f"Error updating knowledge base: {str(e)}")
    
    def get_brands(self):
        """Get list of all known brands"""
        return list(self.data['brands'].keys())
    
    def get_legitimate_domains(self, brand):
        """Get legitimate domains for a brand"""
        if brand in self.data['brands']:
            return self.data['brands'][brand].get('domains', [])
        return []
    
    def get_brand_indicators(self, brand):
        """Get indicators for a brand"""
        if brand in self.data['brands']:
            return self.data['brands'][brand].get('indicators', [])
        return []
    
    def get_templates(self):
        """Get templates for all brands"""
        templates = {}
        for brand, data in self.data['brands'].items():
            templates[brand] = data.get('templates', [])
        return templates
    
    def get_tactics(self):
        """Get all known phishing tactics"""
        return self.data['tactics']
    
    def get_indicators(self):
        """Get all phishing indicators"""
        return self.data['indicators']
    
    def add_template(self, brand, template):
        """Add a new template for a brand"""
        if brand in self.data['brands']:
            if 'templates' not in self.data['brands'][brand]:
                self.data['brands'][brand]['templates'] = []
            
            if template not in self.data['brands'][brand]['templates']:
                self.data['brands'][brand]['templates'].append(template)
                self._save_knowledge_base()
                return True
        return False