"""
PhishLock AI Knowledge Base
A repository of phishing patterns, tactics, and indicators for the RAG system
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional

class PhishingKnowledgeBase:
    def __init__(self, knowledge_file: str = "data/phishing_knowledge.json"):
        """
        Initialize the phishing knowledge base.
        
        Args:
            knowledge_file: Path to the JSON file containing phishing knowledge
        """
        self.knowledge_file = knowledge_file
        self.knowledge = self._load_knowledge()
        self.last_updated = datetime.now()
        
        # Create default knowledge base if it doesn't exist
        if not self.knowledge:
            self._create_default_knowledge()
            self._save_knowledge()
            
    def _load_knowledge(self) -> Dict[str, Any]:
        """Load the knowledge base from file."""
        if os.path.exists(self.knowledge_file):
            try:
                with open(self.knowledge_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading knowledge base: {e}")
        
        # Ensure the directory exists
        os.makedirs(os.path.dirname(self.knowledge_file), exist_ok=True)
        return {}
        
    def _save_knowledge(self) -> None:
        """Save the knowledge base to file."""
        try:
            with open(self.knowledge_file, 'w') as f:
                json.dump(self.knowledge, f, indent=2)
        except Exception as e:
            print(f"Error saving knowledge base: {e}")
            
    def _create_default_knowledge(self) -> None:
        """Create a default knowledge base with common phishing patterns."""
        self.knowledge = {
            "metadata": {
                "version": "1.0",
                "created": datetime.now().isoformat(),
                "updated": datetime.now().isoformat()
            },
            "tactics": {
                "urgency": {
                    "description": "Creating a sense of urgency to force quick, unconsidered actions",
                    "indicators": [
                        "immediate action required",
                        "urgent",
                        "action needed",
                        "expires soon",
                        "limited time",
                        "deadline",
                        "act now",
                        "within 24 hours",
                        "immediate attention",
                        "time sensitive"
                    ],
                    "examples": [
                        "Your account will be suspended within 24 hours if you don't verify your information",
                        "Immediate action required to prevent account termination"
                    ]
                },
                "fear": {
                    "description": "Using fear to manipulate victims into taking actions",
                    "indicators": [
                        "suspicious activity",
                        "unauthorized access",
                        "security alert",
                        "breach",
                        "compromised",
                        "unusual login",
                        "suspicious transaction",
                        "security issue",
                        "fraud",
                        "stolen"
                    ],
                    "examples": [
                        "We've detected suspicious activity on your account",
                        "Unauthorized login attempt detected from [location]"
                    ]
                },
                "greed": {
                    "description": "Exploiting desire for financial gain",
                    "indicators": [
                        "congratulations",
                        "winner",
                        "selected",
                        "prize",
                        "reward",
                        "million",
                        "inheritance",
                        "lottery",
                        "bonus",
                        "free money"
                    ],
                    "examples": [
                        "Congratulations! You've been selected to receive a $1,000,000 prize",
                        "You are the lucky winner of our monthly draw"
                    ]
                },
                "curiosity": {
                    "description": "Exploiting natural curiosity to encourage clicks",
                    "indicators": [
                        "check this out",
                        "you won't believe",
                        "have you seen this",
                        "look what I found",
                        "thought you might be interested",
                        "exclusive content",
                        "private photo",
                        "someone shared",
                        "view document",
                        "interesting article"
                    ],
                    "examples": [
                        "Check out this photo of you that's going viral!",
                        "You won't believe what I just found about you online"
                    ]
                },
                "impersonation": {
                    "description": "Pretending to be a trusted entity",
                    "indicators": [
                        "official notification",
                        "support team",
                        "customer service",
                        "account team",
                        "security department",
                        "helpdesk",
                        "system administrator",
                        "IT department",
                        "CEO",
                        "billing team"
                    ],
                    "examples": [
                        "This is the Microsoft Security Team contacting you about your account",
                        "Apple Support: Action required for your Apple ID"
                    ]
                }
            },
            "brand_impersonation": {
                "microsoft": {
                    "related_domains": ["microsoft.com", "office.com", "live.com", "outlook.com"],
                    "suspicious_patterns": [
                        "microsoft-support",
                        "microsoft-security",
                        "microsoft-verify",
                        "microsoft365",
                        "ms-verify",
                        "ms-support",
                        "office365-support"
                    ],
                    "common_subjects": [
                        "Microsoft 365 Password Expiry",
                        "Unusual sign-in activity",
                        "Microsoft Account Verification",
                        "Your OneDrive is full",
                        "Microsoft Security Alert"
                    ]
                },
                "apple": {
                    "related_domains": ["apple.com", "icloud.com", "itunes.com"],
                    "suspicious_patterns": [
                        "apple-support",
                        "apple-verify",
                        "apple-security",
                        "icloud-verify",
                        "itunes-billing",
                        "apple-id-support"
                    ],
                    "common_subjects": [
                        "Your Apple ID was used to sign in",
                        "Apple purchase receipt",
                        "Verify your Apple ID information",
                        "Your iCloud storage is full",
                        "Receipt for your recent purchase"
                    ]
                },
                "paypal": {
                    "related_domains": ["paypal.com"],
                    "suspicious_patterns": [
                        "paypal-security",
                        "paypal-support",
                        "paypal-service",
                        "paypal-verify",
                        "paypal-resolution",
                        "paypal-secure"
                    ],
                    "common_subjects": [
                        "PayPal account notice",
                        "Your account has been limited",
                        "Suspicious transaction detected",
                        "Confirm your information",
                        "Receipt for your payment"
                    ]
                },
                "amazon": {
                    "related_domains": ["amazon.com", "aws.amazon.com"],
                    "suspicious_patterns": [
                        "amazon-support",
                        "amazon-security",
                        "amazon-prime",
                        "amazon-billing",
                        "amazon-verify",
                        "aws-account"
                    ],
                    "common_subjects": [
                        "Your Amazon order",
                        "Amazon security notification",
                        "Issue with your Amazon order",
                        "Amazon Prime membership",
                        "Action required for your Amazon account"
                    ]
                },
                "google": {
                    "related_domains": ["google.com", "gmail.com", "youtube.com"],
                    "suspicious_patterns": [
                        "google-security",
                        "google-support",
                        "gmail-support",
                        "google-verify",
                        "google-drive-share",
                        "youtube-copyright"
                    ],
                    "common_subjects": [
                        "Security alert for your Google Account",
                        "New sign-in on Chrome",
                        "Document has been shared with you",
                        "YouTube Copyright Strike",
                        "Your Gmail storage is full"
                    ]
                },
                "banks": {
                    "related_domains": [
                        "chase.com", 
                        "bankofamerica.com", 
                        "wellsfargo.com",
                        "citibank.com",
                        "capitalone.com",
                        "tdbank.com",
                        "pnc.com",
                        "usbank.com"
                    ],
                    "suspicious_patterns": [
                        "secure-banking",
                        "bank-verify",
                        "banking-alert",
                        "account-security",
                        "online-banking-support",
                        "bank-notification",
                        "secure-login"
                    ],
                    "common_subjects": [
                        "Important account notification",
                        "Security alert from your bank",
                        "Verify your account information",
                        "Suspicious transaction detected",
                        "Online banking update required",
                        "Account access limited"
                    ]
                }
            },
            "common_phishing_patterns": {
                "url_manipulation": [
                    "typosquatting", 
                    "homograph_attack", 
                    "subdomain_obfuscation",
                    "url_shortening",
                    "misleading_tlds"
                ],
                "content_indicators": [
                    "generic_greeting",
                    "poor_grammar",
                    "mismatched_links",
                    "suspicious_attachments",
                    "request_for_credentials",
                    "fake_security_notifications",
                    "unsolicited_password_resets"
                ],
                "email_header_anomalies": [
                    "domain_mismatch",
                    "suspicious_smtp_paths",
                    "invalid_spf",
                    "invalid_dkim",
                    "invalid_dmarc"
                ]
            },
            "suspicious_file_types": [
                ".exe", ".bat", ".scr", ".js", ".vbs", ".hta", ".msi",
                ".jar", ".cmd", ".ps1", ".wsf", ".reg", ".lnk"
            ]
        }
    
    def query_knowledge(self, query_type: str, query_value: Optional[str] = None) -> Any:
        """
        Query the knowledge base.
        
        Args:
            query_type: Type of query (e.g., "tactics", "brand_impersonation")
            query_value: Optional specific value to query for (e.g., "microsoft")
            
        Returns:
            The requested knowledge or None if not found
        """
        if query_type in self.knowledge:
            if query_value and query_value in self.knowledge[query_type]:
                return self.knowledge[query_type][query_value]
            return self.knowledge[query_type]
        return None
    
    def get_all_tactics(self) -> Dict[str, Any]:
        """Get all psychological tactics used in phishing."""
        return self.knowledge.get("tactics", {})
    
    def get_tactic_indicators(self, tactic: str) -> List[str]:
        """Get indicators for a specific psychological tactic."""
        tactics = self.knowledge.get("tactics", {})
        if tactic in tactics:
            return tactics[tactic].get("indicators", [])
        return []
    
    def get_brand_info(self, brand: str) -> Dict[str, Any]:
        """Get information about a specific brand impersonation."""
        brands = self.knowledge.get("brand_impersonation", {})
        if brand in brands:
            return brands[brand]
        return {}
    
    def get_legitimate_domains(self, brand: str) -> List[str]:
        """Get legitimate domains for a specific brand."""
        brand_info = self.get_brand_info(brand)
        return brand_info.get("related_domains", [])
    
    def get_all_legitimate_domains(self) -> List[str]:
        """Get all legitimate domains from known brands."""
        domains = []
        brands = self.knowledge.get("brand_impersonation", {})
        for brand_info in brands.values():
            domains.extend(brand_info.get("related_domains", []))
        return domains
    
    def get_suspicious_patterns(self, brand: str) -> List[str]:
        """Get suspicious patterns for a specific brand."""
        brand_info = self.get_brand_info(brand)
        return brand_info.get("suspicious_patterns", [])
    
    def get_suspicious_file_types(self) -> List[str]:
        """Get a list of suspicious file types."""
        return self.knowledge.get("suspicious_file_types", [])
    
    def add_phishing_pattern(self, pattern_type: str, pattern_value: str) -> None:
        """
        Add a new phishing pattern to the knowledge base.
        
        Args:
            pattern_type: Type of pattern (e.g., "tactics.urgency.indicators")
            pattern_value: Value to add
        """
        path = pattern_type.split('.')
        current = self.knowledge
        
        # Navigate to the correct location in the knowledge base
        for i, key in enumerate(path[:-1]):
            if key not in current:
                current[key] = {}
            current = current[key]
        
        # Add the value
        last_key = path[-1]
        if last_key not in current:
            current[last_key] = []
        
        if pattern_value not in current[last_key]:
            current[last_key].append(pattern_value)
            self.knowledge["metadata"]["updated"] = datetime.now().isoformat()
            self._save_knowledge()

# Example usage
if __name__ == "__main__":
    kb = PhishingKnowledgeBase()
    
    # Get all urgency indicators
    urgency_indicators = kb.get_tactic_indicators("urgency")
    print(f"Urgency indicators: {urgency_indicators}")
    
    # Get legitimate Microsoft domains
    microsoft_domains = kb.get_legitimate_domains("microsoft")
    print(f"Legitimate Microsoft domains: {microsoft_domains}")