"""
PhishLock AI Behavioral Analyzer
Analyzes messages for psychological manipulation tactics common in phishing
"""

import re
from typing import Dict, List, Any, Tuple
from collections import Counter

class BehavioralAnalyzer:
    def __init__(self):
        """Initialize the behavioral analyzer with pre-defined patterns."""
        # Urgency patterns
        self.urgency_patterns = [
            r'\b(urgent|immediately|asap|right away|promptly|time-sensitive)\b',
            r'\b(act now|expir(e|es|ed|ing)|within \d+ (hour|day|minute)s?)\b',
            r'\b(limited time|deadline|running out|last chance)\b',
            r'\b(quick|immediate|prompt) (action|attention|response) (required|needed)\b',
            r'\baccount.{1,20}(suspend|terminat|cancel|clos|block)',
            r'\b(don\'t|do not) delay\b',
            r'\baction (needed|required)\b'
        ]
        
        # Fear-based patterns
        self.fear_patterns = [
            r'\b(suspicious|unauthorized|unusual) (activity|access|login|sign-in|transaction)\b',
            r'\bsecurity (issue|problem|concern|violation|breach|incident|alert|warning)\b',
            r'\baccount.{1,20}(compromised|hacked|breached|at risk|vulnerable)\b',
            r'\b(detect|notic|found|identify).{1,20}(suspicious|unusual|unauthorized|strange)\b',
            r'\b(fraud|fraudulent|scam|theft|stolen)\b',
            r'\byour (information|data|identity).{1,20}(risk|danger|exposed|compromised|vulnerable)\b',
            r'\bviolation of.{1,20}(policy|agreement|terms|security)\b',
            r'\blegal.{1,20}(action|consequence|proceeding|notice)\b'
        ]
        
        # Authority patterns
        self.authority_patterns = [
            r'\b(official|authorized|mandatory) (notice|notification|communication|message|alert)\b',
            r'\b(compliance|policy|regulation|requirement)\b',
            r'\b(legal|regulatory|mandatory) (requirement|obligation|compliance|action)\b',
            r'\b(we|I).{1,20}(Director|Manager|Administrator|Officer|CEO|President|Chairman|Head of)\b',
            r'\b(security|management|administrative|executive) team\b',
            r'\b(corporate|company|enterprise|business|organizational) (policy|directive|mandate)\b',
            r'\b(verify|confirm|validate|authenticate).{1,20}(compliance|adherence)\b'
        ]
        
        # Reward/greed patterns
        self.reward_patterns = [
            r'\b(congratulations|winner|won|award|prize|reward|discount|bonus|free|gift)\b',
            r'\b(selected|chosen|exclusive|special) (offer|promotion|deal|discount)\b',
            r'\b(claim|redeem|collect) (your|the) (prize|reward|gift|offer|money)\b',
            r'\byou.{1,20}(won|earned|awarded|granted|entitled to|qualify for)\b',
            r'\b(million|thousand|hundred).{1,30}(dollar|euro|pound|USD|EUR|GBP)\b',
            r'\b(lottery|jackpot|sweepstake|draw|competition)\b',
            r'\blimited.{1,20}(offer|promotion|opportunity|deal)\b',
            r'\b(inheritance|beneficiary|next of kin|relative)\b'
        ]
        
        # Request for sensitive info patterns
        self.sensitive_request_patterns = [
            r'\b(confirm|update|verify|validate|provide).{1,30}(password|username|login|credential)\b',
            r'\b(SSN|social security|tax ID|EIN|passport number|driver\'?s license)\b',
            r'\b(credit card|card number|CVV|expiration date|security code)\b',
            r'\b(bank account|routing number|sort code|IBAN|PIN)\b',
            r'\bID.{1,20}(verification|confirm|validate|authenticate)\b',
            r'\b(personal|private|sensitive|confidential).{1,20}information\b',
            r'\b(click|follow).{1,30}(link|button|attachment).{1,30}(verify|confirm|update|sign in|login)\b',
            r'\b(form|document).{1,30}(fill|complete|submit)\b'
        ]
        
        # Impersonation patterns
        self.impersonation_patterns = [
            r'\b(Microsoft|Apple|Google|Amazon|PayPal|Netflix|Facebook|Twitter|Instagram|Bank)\b',
            r'\b(tech support|customer service|help desk|support team|service team)\b',
            r'\b(IT|technical|system) (department|administrator|admin|team|specialist|support)\b',
            r'\b(account|security|payment|billing) (team|department|specialist|group|division)\b',
            r'\b(automated|system) (message|notification|alert)\b',
            r'\b(copyright|DMCA|intellectual property|legal).{1,30}(violation|infringement|notice)\b',
            r'\b(CEO|CFO|CIO|CTO|founder|executive).{1,30}(request|asking|needs|requires)\b'
        ]
        
        # Pressure/manipulation patterns
        self.pressure_patterns = [
            r'\b(only|just).{1,10}(few|limited|available).{1,10}(left|remaining)\b',
            r'\b(thousands|many|everyone|others).{1,20}already.{1,20}(signed up|registered|claimed|participated)\b',
            r'\b(don\'t|do not).{1,20}(miss out|lose|wait|hesitate|delay)\b',
            r'\b(guaranteed|promise|assure|ensure|confirm).{1,20}(success|result|outcome|benefit)\b',
            r'\b(no one|nobody).{1,20}(know|discover|find out|realize)\b',
            r'\b(secret|confidential|private|exclusive|special).{1,20}(method|technique|approach|strategy|offer)\b',
            r'\b(before|until).{1,10}(too late|expire|end|run out)\b',
            r'\b(must|need to|have to|required to).{1,20}(act|respond|reply|click|follow|complete)\b'
        ]
        
        # Generic greeting patterns (indicates potential phishing)
        self.generic_greeting_patterns = [
            r'\b(dear|hello|hi|greetings).{1,20}(customer|user|client|member|account holder|valued)\b',
            r'\b(dear|hello|hi|greetings).{1,20}(sir|madam|valued customer)\b',
            r'\b(attention|notice to|alert to).{1,20}(user|customer|client|account holder)\b'
        ]
        
        # Poor grammar patterns (indicates potential phishing)
        self.poor_grammar_patterns = [
            r'\bkindly\b',
            r'\bdo the needful\b',
            r'\brevert back\b',
            r'\bpls\b',
            r'\b100\% guarantee\b',
            r'\bto be done\b',
            r'\byours? faithfully\b',
            r'\bgreetings of the day\b'
        ]
        
        # Compile all patterns for performance
        self.all_patterns = {
            'urgency': [re.compile(p, re.IGNORECASE) for p in self.urgency_patterns],
            'fear': [re.compile(p, re.IGNORECASE) for p in self.fear_patterns],
            'authority': [re.compile(p, re.IGNORECASE) for p in self.authority_patterns],
            'reward': [re.compile(p, re.IGNORECASE) for p in self.reward_patterns],
            'sensitive_request': [re.compile(p, re.IGNORECASE) for p in self.sensitive_request_patterns],
            'impersonation': [re.compile(p, re.IGNORECASE) for p in self.impersonation_patterns],
            'pressure': [re.compile(p, re.IGNORECASE) for p in self.pressure_patterns],
            'generic_greeting': [re.compile(p, re.IGNORECASE) for p in self.generic_greeting_patterns],
            'poor_grammar': [re.compile(p, re.IGNORECASE) for p in self.poor_grammar_patterns]
        }
        
    def analyze_text(self, text: str) -> Dict[str, Any]:
        """
        Analyze text for behavioral manipulation patterns.
        
        Args:
            text: The text to analyze
            
        Returns:
            Dictionary with analysis results
        """
        results = {
            'tactics_detected': {},
            'overall_score': 0.0,
            'manipulative_phrases': [],
            'primary_tactic': None,
            'dominant_tactics': []
        }
        
        # Track all matched phrases
        all_matches = []
        tactic_counts = Counter()
        
        # Analyze each pattern type
        for tactic, patterns in self.all_patterns.items():
            matches = []
            
            for pattern in patterns:
                found = pattern.findall(text)
                if found:
                    matches.extend(found)
            
            if matches:
                # Calculate score based on number of matches and pattern type
                # Different weights for different patterns
                if tactic in ['sensitive_request', 'impersonation']:
                    weight = 0.25  # Higher weight for sensitive request/impersonation
                elif tactic in ['urgency', 'fear']:
                    weight = 0.2  # High weight for urgency and fear tactics
                elif tactic == 'poor_grammar':
                    weight = 0.1  # Lower weight for grammar issues
                else:
                    weight = 0.15  # Default weight
                
                # Calculate score, capped at max per category
                score = min(0.9, len(matches) * weight)
                
                results['tactics_detected'][tactic] = {
                    'score': score,
                    'matches': matches[:5],  # Limit to 5 examples
                    'count': len(matches)
                }
                
                tactic_counts[tactic] = len(matches)
                all_matches.extend(matches[:5])
        
        # Calculate overall score
        if results['tactics_detected']:
            # Sum of all scores, with diminishing returns
            scores = [score['score'] for score in results['tactics_detected'].values()]
            total_score = sum(scores)
            
            # Apply diminishing returns formula: 1 - (1 - s1) * (1 - s2) * ... * (1 - sn)
            # This ensures scores don't exceed 1.0 even with multiple tactics
            diminished_score = 1.0
            for score in scores:
                diminished_score *= (1.0 - score)
            
            results['overall_score'] = 1.0 - diminished_score
            
            # Find dominant tactics (highest scores)
            if tactic_counts:
                # Get most common tactics
                most_common = tactic_counts.most_common(3)
                results['dominant_tactics'] = [tactic for tactic, count in most_common if count > 1]
                if most_common:
                    results['primary_tactic'] = most_common[0][0]
        
        # Save unique manipulation phrases
        results['manipulative_phrases'] = list(set(all_matches))
        
        return results
    
    def analyze_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a message for behavioral manipulation.
        
        Args:
            message: A dictionary containing 'sender', 'subject', and 'content' keys
            
        Returns:
            Dictionary with analysis results
        """
        # Extract components
        subject = message.get('subject', '')
        content = message.get('content', '')
        sender = message.get('sender', '')
        
        # Analyze subject and content separately
        subject_analysis = self.analyze_text(subject) if subject else None
        content_analysis = self.analyze_text(content) if content else None
        
        # Combined analysis
        combined_text = f"{subject} {content}"
        combined_analysis = self.analyze_text(combined_text)
        
        # Check for sender red flags (simplified)
        sender_score = 0.0
        sender_issues = []
        
        # Check for suspicious sender patterns
        suspicious_sender_patterns = [
            (r'@.*\.(xyz|top|club|online|site|info|co)\b', 'Suspicious TLD'),
            (r'@.*-.*\.', 'Hyphenated domain'),
            (r'@.*\d+\.', 'Numeric domain'),
            (r'(noreply|no-reply|no\.reply|donotreply|alert|security|verify|support)@', 'Generic sender'),
            (r'@(gmail|yahoo|hotmail|outlook|aol|protonmail)\.(com|net|org)', 'Consumer email for business communication')
        ]
        
        for pattern, issue in suspicious_sender_patterns:
            if re.search(pattern, sender, re.IGNORECASE):
                sender_score += 0.15
                sender_issues.append(issue)
        
        # Generate recommendations based on analysis
        recommendations = []
        if combined_analysis['overall_score'] > 0.7:
            recommendations.append("High probability of phishing. Do not engage with this message.")
        elif combined_analysis['overall_score'] > 0.4:
            recommendations.append("Suspicious message. Verify through other channels before taking any action.")
        
        # Add specific recommendations based on tactics
        if 'sensitive_request' in combined_analysis['tactics_detected']:
            recommendations.append("Never provide sensitive information via email. Legitimate organizations will not ask for passwords or financial information.")
        
        if 'urgency' in combined_analysis['tactics_detected']:
            recommendations.append("Be cautious of urgent requests. Take time to verify before acting.")
        
        if 'impersonation' in combined_analysis['tactics_detected']:
            recommendations.append("Verify the sender's identity through official channels, not using contact information in the message.")
        
        # Combine results
        return {
            'combined_score': combined_analysis['overall_score'],
            'subject_score': subject_analysis['overall_score'] if subject_analysis else 0.0,
            'content_score': content_analysis['overall_score'] if content_analysis else 0.0,
            'sender_score': min(1.0, sender_score),
            'tactics_detected': combined_analysis['tactics_detected'],
            'dominant_tactics': combined_analysis['dominant_tactics'],
            'primary_tactic': combined_analysis['primary_tactic'],
            'manipulative_phrases': combined_analysis['manipulative_phrases'],
            'sender_issues': sender_issues,
            'recommendations': recommendations,
            'is_suspicious': combined_analysis['overall_score'] > 0.5 or sender_score > 0.3
        }