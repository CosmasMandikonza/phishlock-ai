"""
PhishLock AI RAG Analyzer
Implements Retrieval-Augmented Generation for phishing detection
"""

import re
from typing import Dict, List, Tuple, Any, Optional
from openai import OpenAI
import json
import os
from dotenv import load_dotenv

from .knowledge_base import PhishingKnowledgeBase

# Load environment variables
load_dotenv()

class RAGPhishingAnalyzer:
    def __init__(self):
        """Initialize the RAG-based phishing analyzer."""
        self.knowledge_base = PhishingKnowledgeBase()
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        
    def retrieve_relevant_knowledge(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Retrieve relevant knowledge from the knowledge base for the given message.
        
        Args:
            message: A dictionary containing 'sender', 'subject', and 'content' keys
            
        Returns:
            Dictionary of relevant knowledge for the RAG system
        """
        relevant_knowledge = {
            "tactics": {},
            "brand_impersonation": None,
            "patterns": []
        }
        
        # Combine message components for analysis
        combined_text = f"{message.get('subject', '')} {message.get('content', '')}"
        combined_text = combined_text.lower()
        
        # Extract psychological tactics
        all_tactics = self.knowledge_base.get_all_tactics()
        for tactic_name, tactic_info in all_tactics.items():
            indicators = tactic_info.get("indicators", [])
            found_indicators = []
            
            for indicator in indicators:
                if indicator.lower() in combined_text:
                    found_indicators.append(indicator)
                    
            if found_indicators:
                relevant_knowledge["tactics"][tactic_name] = {
                    "description": tactic_info.get("description", ""),
                    "found_indicators": found_indicators,
                    "score": min(1.0, len(found_indicators) / 10.0)  # Normalize score between 0 and 1
                }
        
        # Check for brand impersonation
        brands = self.knowledge_base.knowledge.get("brand_impersonation", {})
        impersonated_brand = None
        max_score = 0
        
        for brand_name, brand_info in brands.items():
            score = 0
            legitimate_domains = brand_info.get("related_domains", [])
            suspicious_patterns = brand_info.get("suspicious_patterns", [])
            common_subjects = brand_info.get("common_subjects", [])
            
            # Check sender domain against legitimate domains
            sender = message.get('sender', '').lower()
            sender_domain = sender.split('@')[-1] if '@' in sender else sender
            
            # If sender pretends to be from a legitimate brand but domain doesn't match
            brand_mentioned = False
            for domain in legitimate_domains:
                if domain in combined_text or brand_name.lower() in combined_text:
                    brand_mentioned = True
                    break
                    
            if brand_mentioned and not any(domain == sender_domain for domain in legitimate_domains):
                score += 0.5  # Strong indicator of brand impersonation
            
            # Check for suspicious patterns in sender or domain
            for pattern in suspicious_patterns:
                if pattern.lower() in sender.lower():
                    score += 0.3
            
            # Check subject against common phishing subjects for this brand
            subject = message.get('subject', '').lower()
            for common_subject in common_subjects:
                if common_subject.lower() in subject:
                    score += 0.2
            
            if score > max_score:
                max_score = score
                impersonated_brand = {
                    "name": brand_name,
                    "score": score,
                    "legitimate_domains": legitimate_domains,
                    "detected_patterns": [p for p in suspicious_patterns if p.lower() in sender.lower()]
                }
        
        if impersonated_brand and impersonated_brand["score"] > 0.2:
            relevant_knowledge["brand_impersonation"] = impersonated_brand
        
        # Identify common phishing patterns
        patterns = self.knowledge_base.knowledge.get("common_phishing_patterns", {})
        for pattern_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                # For simplicity, we're just checking if the pattern name is in the text
                # In a real implementation, we'd have more sophisticated pattern matching
                if pattern.replace("_", " ") in combined_text:
                    relevant_knowledge["patterns"].append({
                        "type": pattern_type,
                        "pattern": pattern
                    })
        
        return relevant_knowledge
    
    def generate_prompt_with_context(self, message: Dict[str, Any], relevant_knowledge: Dict[str, Any]) -> str:
        """
        Generate a prompt for the LLM with relevant context from the knowledge base.
        
        Args:
            message: A dictionary containing 'sender', 'subject', and 'content' keys
            relevant_knowledge: Dictionary of relevant knowledge from retrieve_relevant_knowledge()
            
        Returns:
            A prompt string for the LLM
        """
        prompt = f"""
        Analyze this email for phishing:
        
        From: {message.get('sender', '')}
        Subject: {message.get('subject', 'No subject')}
        
        Content:
        {message.get('content', '')}
        
        ==========
        CONTEXT FROM PHISHING KNOWLEDGE BASE:
        """
        
        # Add information about detected tactics
        if relevant_knowledge["tactics"]:
            prompt += "\nPsychological Tactics Detected:\n"
            for tactic_name, tactic_info in relevant_knowledge["tactics"].items():
                prompt += f"- {tactic_name.upper()}: {tactic_info['description']}\n"
                prompt += f"  Found indicators: {', '.join(tactic_info['found_indicators'])}\n"
        
        # Add information about brand impersonation
        if relevant_knowledge["brand_impersonation"]:
            brand = relevant_knowledge["brand_impersonation"]
            prompt += f"\nPossible {brand['name'].upper()} Impersonation Detected:\n"
            prompt += f"- Legitimate domains for {brand['name']}: {', '.join(brand['legitimate_domains'])}\n"
            if brand["detected_patterns"]:
                prompt += f"- Suspicious patterns: {', '.join(brand['detected_patterns'])}\n"
        
        # Add information about common phishing patterns
        if relevant_knowledge["patterns"]:
            prompt += "\nCommon Phishing Patterns Detected:\n"
            for pattern in relevant_knowledge["patterns"]:
                prompt += f"- {pattern['type']}: {pattern['pattern'].replace('_', ' ')}\n"
        
        prompt += """
        ==========
        
        Based on this analysis and your expertise, determine if this is a phishing attempt.
        Consider:
        1. Sender authenticity
        2. Urgency/pressure tactics
        3. Requests for sensitive information
        4. Suspicious links or attachments
        5. Brand impersonation
        6. Language and grammar issues
        
        Return your analysis as JSON with these fields:
        - is_suspicious (boolean): true if it's phishing, false if it's legitimate
        - confidence (number between 0 and 1): your confidence in this assessment
        - reasons (array of strings): specific reasons for your decision
        - tactics_used (array of strings): psychological tactics identified (e.g., "urgency", "fear")
        - impersonated_brand (string or null): name of impersonated brand, if any
        """
        
        return prompt
    
    def calculate_heuristic_score(self, message: Dict[str, Any], relevant_knowledge: Dict[str, Any]) -> float:
        """
        Calculate a phishing probability score based on heuristics.
        
        Args:
            message: A dictionary containing 'sender', 'subject', and 'content' keys
            relevant_knowledge: Dictionary of relevant knowledge
            
        Returns:
            A score between 0 and 1 indicating phishing probability
        """
        score = 0.0
        
        # Score based on psychological tactics
        tactic_score = sum(tactic["score"] for tactic in relevant_knowledge["tactics"].values())
        score += min(0.5, tactic_score * 0.25)  # Max 0.5 from tactics
        
        # Score based on brand impersonation
        if relevant_knowledge["brand_impersonation"]:
            score += relevant_knowledge["brand_impersonation"]["score"] * 0.3  # Max 0.3 from brand impersonation
        
        # Score based on common patterns
        score += min(0.2, len(relevant_knowledge["patterns"]) * 0.05)  # Max 0.2 from patterns
        
        # Check for suspicious content indicators
        content = message.get('content', '').lower()
        subject = message.get('subject', '').lower()
        
        # Check for urgency indicators in subject
        urgency_words = ["urgent", "immediately", "alert", "warning", "action required"]
        if any(word in subject for word in urgency_words):
            score += 0.1
        
        # Check for request for sensitive information
        sensitive_requests = ["password", "credential", "credit card", "ssn", "social security", "account number"]
        if any(phrase in content for phrase in sensitive_requests):
            score += 0.2
        
        # Check for poor grammar or spelling (simplified check)
        grammar_issues = [
            "kindly", "do the needful", "valued customer", "dear customer", 
            "dear user", "dear account holder", "100%", "urgent attention"
        ]
        if any(issue in content for issue in grammar_issues):
            score += 0.1
        
        return min(1.0, score)  # Ensure score is between 0 and 1
    
    def analyze_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a message for phishing using RAG and LLM.
        
        Args:
            message: A dictionary containing 'sender', 'subject', and 'content' keys
            
        Returns:
            Analysis results
        """
        # Retrieve relevant knowledge
        relevant_knowledge = self.retrieve_relevant_knowledge(message)
        
        # Calculate heuristic score
        heuristic_score = self.calculate_heuristic_score(message, relevant_knowledge)
        
        # If heuristic score is very high or very low, we might skip LLM to save costs
        skip_llm = heuristic_score > 0.85 or heuristic_score < 0.15
        
        llm_result = None
        if not skip_llm:
            # Generate prompt with context
            prompt = self.generate_prompt_with_context(message, relevant_knowledge)
            
            try:
                # Call the LLM
                response = self.client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity expert analyzing emails for phishing."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.2
                )
                
                # Extract and parse the LLM response
                content = response.choices[0].message.content
                
                # Try to parse JSON from the LLM response
                try:
                    # Look for JSON pattern in the response
                    start_idx = content.find('{')
                    end_idx = content.rfind('}') + 1
                    
                    if start_idx >= 0 and end_idx > start_idx:
                        json_str = content[start_idx:end_idx]
                        llm_result = json.loads(json_str)
                    else:
                        # Fallback if JSON extraction fails
                        is_suspicious = "phishing" in content.lower() or "suspicious" in content.lower()
                        llm_result = {
                            "is_suspicious": is_suspicious,
                            "confidence": 0.6 if is_suspicious else 0.4,
                            "reasons": ["AI detected suspicious patterns" if is_suspicious else "No suspicious patterns detected"],
                            "tactics_used": list(relevant_knowledge["tactics"].keys()),
                            "impersonated_brand": relevant_knowledge["brand_impersonation"]["name"] if relevant_knowledge["brand_impersonation"] else None
                        }
                except Exception as e:
                    print(f"Error parsing LLM response: {e}")
                    llm_result = None
            except Exception as e:
                print(f"Error calling LLM: {e}")
                llm_result = None
        
        # Combine heuristic and LLM analysis
        if llm_result:
            # Weighted average of heuristic and LLM scores
            final_score = (heuristic_score * 0.4) + (llm_result.get("confidence", 0.5) * 0.6)
            final_is_suspicious = llm_result.get("is_suspicious", False)
            
            # In case of high disagreement, lean toward suspicion for safety
            if abs(heuristic_score - llm_result.get("confidence", 0.5)) > 0.4:
                final_is_suspicious = heuristic_score > 0.5 or llm_result.get("is_suspicious", False)
            
            reasons = llm_result.get("reasons", [])
            
            # Add heuristic reasons
            if relevant_knowledge["brand_impersonation"]:
                brand = relevant_knowledge["brand_impersonation"]["name"]
                reasons.append(f"Potential {brand} brand impersonation detected")
            
            for tactic_name in relevant_knowledge["tactics"].keys():
                if tactic_name not in str(reasons).lower():
                    reasons.append(f"{tactic_name.capitalize()} tactics detected in message")
            
            return {
                "is_suspicious": final_is_suspicious,
                "confidence": final_score,
                "reasons": reasons,
                "tactics_used": llm_result.get("tactics_used", list(relevant_knowledge["tactics"].keys())),
                "impersonated_brand": llm_result.get("impersonated_brand") or (
                    relevant_knowledge["brand_impersonation"]["name"] if relevant_knowledge["brand_impersonation"] else None
                ),
                "knowledge_used": {
                    "tactics": list(relevant_knowledge["tactics"].keys()),
                    "brand_impersonation": relevant_knowledge["brand_impersonation"]["name"] if relevant_knowledge["brand_impersonation"] else None,
                    "patterns": [p["pattern"] for p in relevant_knowledge["patterns"]]
                },
                "heuristic_score": heuristic_score
            }
        else:
            # Fallback to heuristic analysis only
            is_suspicious = heuristic_score > 0.5
            reasons = []
            
            # Generate reasons based on heuristics
            if relevant_knowledge["brand_impersonation"]:
                brand = relevant_knowledge["brand_impersonation"]["name"]
                reasons.append(f"Potential {brand} brand impersonation detected")
            
            for tactic_name, tactic_info in relevant_knowledge["tactics"].items():
                reasons.append(f"{tactic_name.capitalize()} tactics detected: {', '.join(tactic_info['found_indicators'][:3])}")
            
            if not reasons and is_suspicious:
                reasons.append("Suspicious patterns detected by heuristic analysis")
            elif not reasons:
                reasons.append("No suspicious patterns detected")
            
            return {
                "is_suspicious": is_suspicious,
                "confidence": heuristic_score,
                "reasons": reasons,
                "tactics_used": list(relevant_knowledge["tactics"].keys()),
                "impersonated_brand": relevant_knowledge["brand_impersonation"]["name"] if relevant_knowledge["brand_impersonation"] else None,
                "knowledge_used": {
                    "tactics": list(relevant_knowledge["tactics"].keys()),
                    "brand_impersonation": relevant_knowledge["brand_impersonation"]["name"] if relevant_knowledge["brand_impersonation"] else None,
                    "patterns": [p["pattern"] for p in relevant_knowledge["patterns"]]
                },
                "heuristic_score": heuristic_score
            }