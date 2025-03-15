"""
Simplified PhishLock AI Demo
This removes dependency issues while demonstrating core functionality
"""
import os
import json
import re
from datetime import datetime

class SimpleBehavioralAnalyzer:
    def __init__(self):
        self.urgency_patterns = [
            r'\b(urgent|immediately|asap|right away|promptly|time-sensitive)\b',
            r'\b(act now|expir(e|es|ed|ing)|within \d+ (hour|day|minute)s?)\b'
        ]
        self.fear_patterns = [
            r'\b(suspicious|unauthorized|unusual) (activity|access|login|sign-in|transaction)\b',
            r'\b(security (issue|problem|concern|violation|breach|incident|alert|warning))\b'
        ]
        
    def analyze_message(self, message):
        content = message.get('content', '')
        combined_score = 0.0
        tactics_detected = {}
        
        # Check for urgency patterns
        urgency_matches = []
        for pattern in self.urgency_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                urgency_matches.extend(matches)
        
        if urgency_matches:
            tactics_detected['urgency'] = {
                'score': min(0.8, len(urgency_matches) * 0.2),
                'matches': urgency_matches[:3]
            }
            combined_score += len(urgency_matches) * 0.2
            
        # Check for fear patterns
        fear_matches = []
        for pattern in self.fear_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                fear_matches.extend(matches)
        
        if fear_matches:
            tactics_detected['fear'] = {
                'score': min(0.8, len(fear_matches) * 0.25),
                'matches': fear_matches[:3]
            }
            combined_score += len(fear_matches) * 0.25
            
        # Cap the score at 1.0
        combined_score = min(1.0, combined_score)
        
        # Generate result
        return {
            'combined_score': combined_score,
            'tactics_detected': tactics_detected,
            'is_suspicious': combined_score > 0.5,
            'primary_tactic': 'urgency' if 'urgency' in tactics_detected else 'fear' if 'fear' in tactics_detected else None
        }

class SimpleURLExtractor:
    def extract_urls(self, text):
        # Basic URL regex
        url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
        return url_pattern.findall(text)
    
    def analyze_urls_in_text(self, text):
        urls = self.extract_urls(text)
        suspicious_count = 0
        
        # Simple check for suspicious domains
        suspicious_tlds = ['xyz', 'top', 'club', 'online', 'site']
        for url in urls:
            if any(tld in url for tld in suspicious_tlds):
                suspicious_count += 1
        
        return {
            'urls_found': urls,
            'url_count': len(urls),
            'suspicious_count': suspicious_count,
            'overall_score': suspicious_count / max(1, len(urls)) if urls else 0,
            'overall_suspicious': suspicious_count > 0
        }

def analyze_message():
    # Sample messages to analyze
    test_messages = [
        {
            "name": "Bank phishing example",
            "sender": "secure-banking@bank0famerica-secure.com",
            "subject": "URGENT: Your account requires verification",
            "content": "Dear valued customer,\n\nWe have detected unusual activity on your Bank of America account. To ensure your account security, please verify your information immediately by clicking on the link below:\n\nhttps://bank0famerica-secure.com/verify\n\nFailure to verify within 24 hours will result in your account being temporarily suspended.\n\nThank you,\nBank of America Security Team"
        },
        {
            "name": "Password reset phishing",
            "sender": "noreply@microsoft-verify.xyz",
            "subject": "Your Microsoft password is about to expire",
            "content": "Your Microsoft 365 password is set to expire today. To ensure uninterrupted access to your email and services, please update your password immediately.\n\nClick here to reset: https://ms-account-verify.xyz/password-reset\n\nIgnoring this message will result in loss of access to your account.\n\nThank you,\nMicrosoft Security"
        },
        {
            "name": "Legitimate message",
            "sender": "newsletter@github.com",
            "subject": "GitHub Changelog: What's new this month",
            "content": "Here's what's new on GitHub this month:\n\n- Improved Copilot features\n- New team collaboration tools\n- Enhanced security features\n\nCheck out the details at https://github.blog/changelog\n\nYour GitHub Team"
        }
    ]
    
    # Initialize analyzers
    behavioral_analyzer = SimpleBehavioralAnalyzer()
    url_extractor = SimpleURLExtractor()
    
    # Process each message
    for message in test_messages:
        print(f"\n\n===== Analyzing: {message['name']} =====")
        print(f"From: {message['sender']}")
        print(f"Subject: {message['subject']}")
        print(f"Content snippet: {message['content'][:100]}...\n")
        
        # Analyze behavior
        behavior_result = behavioral_analyzer.analyze_message(message)
        
        # Extract and analyze URLs
        url_analysis = url_extractor.analyze_urls_in_text(message['content'])
        
        # Combine results for final decision
        is_suspicious = behavior_result['is_suspicious'] or url_analysis['overall_suspicious']
        confidence = (behavior_result['combined_score'] * 0.7) + (url_analysis['overall_score'] * 0.3)
        
        # Display results
        print(f"VERDICT: {'⚠️ SUSPICIOUS' if is_suspicious else '✅ LEGITIMATE'}")
        print(f"Confidence: {confidence:.2f} (0-1 scale)")
        
        if behavior_result['tactics_detected']:
            print("\nManipulation tactics detected:")
            for tactic, details in behavior_result['tactics_detected'].items():
                print(f"- {tactic.upper()} (score: {details['score']:.2f})")
                if details['matches']:
                    print(f"  Examples: {', '.join(str(m) for m in details['matches'])}")
        
        if url_analysis['urls_found']:
            print("\nURLs found:")
            for url in url_analysis['urls_found']:
                suspicious = any(tld in url for tld in ['xyz', 'top', 'club', 'online', 'site'])
                print(f"- {url} {'⚠️ (suspicious)' if suspicious else ''}")
        
        # Generate recommendation
        if is_suspicious:
            print("\nRECOMMENDATION:")
            if behavior_result['primary_tactic'] == 'urgency':
                print("This message uses urgency tactics to pressure you. Legitimate organizations rarely use these tactics.")
            elif 'microsoft' in message['sender'].lower() or 'microsoft' in message['content'].lower():
                print("This message appears to be impersonating Microsoft. Do not interact with it or click any links.")
            elif 'bank' in message['sender'].lower() or 'bank' in message['content'].lower():
                print("This message appears to be impersonating a bank. Contact your bank directly using their official website or phone number.")
            else:
                print("This message shows signs of being a phishing attempt. Exercise caution and verify through official channels before taking any action.")
        else:
            print("\nRECOMMENDATION: This message appears legitimate, but always verify sensitive requests through other channels.")

if __name__ == "__main__":
    print("PhishLock AI - Simple Demonstration")
    print("This is a simplified version to demonstrate core functionality")
    print("=" * 70)
    
    analyze_message()
    
    print("\nDemo complete! This simplified version demonstrates the core functionality without FastAPI dependencies.")