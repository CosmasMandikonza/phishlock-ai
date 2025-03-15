"""
LLM-based phishing detection component for PhishLock AI
"""
import os
import requests
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class LLMAnalyzer:
    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
        self.api_provider = "openai" if os.getenv("OPENAI_API_KEY") else "anthropic"
        self.cache = {}  # Simple in-memory cache
        
    def detect_sophisticated_phishing(self, message):
        """
        Use LLM to detect sophisticated phishing attempts that might bypass traditional rules
        
        Args:
            message (dict): Message containing 'sender', 'subject', and 'content'
            
        Returns:
            dict: Analysis results including score and reasoning
        """
        # Create a cache key
        cache_key = f"{message['sender']}|{message['subject']}|{message['content'][:100]}"
        
        # Check cache first
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        # Prepare the prompt
        prompt = self._create_analysis_prompt(message)
        
        # Get LLM analysis
        if self.api_provider == "openai":
            analysis = self._query_openai(prompt)
        else:
            analysis = self._query_anthropic(prompt)
            
        # Cache the result
        self.cache[cache_key] = analysis
        
        return analysis
    
    def _create_analysis_prompt(self, message):
        """Create a detailed prompt for the LLM"""
        return f"""
        You are an expert at detecting sophisticated phishing attempts. Analyze this message and determine if it appears to be a phishing attempt.
        
        SENDER: {message['sender']}
        SUBJECT: {message['subject']}
        CONTENT: {message['content']}
        
        Provide your analysis in the following JSON format:
        {{
            "is_phishing": true/false,
            "confidence": 0-1 (float),
            "techniques_detected": ["list", "of", "techniques"],
            "reasoning": "Detailed explanation of your reasoning",
            "score": 0-1 (float)
        }}
        
        Consider the following in your analysis:
        1. Brand impersonation
        2. Psychological manipulation tactics
        3. Urgency or pressure tactics
        4. Suspicious links or domains
        5. Grammatical errors or odd phrasing
        6. Request for sensitive information
        7. Inconsistencies in sender information
        8. Use of threatening language
        """
    
    def _query_openai(self, prompt):
        """Query OpenAI API"""
        try:
            if not self.api_key:
                return self._fallback_analysis()
                
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            data = {
                "model": "gpt-3.5-turbo",
                "messages": [{"role": "system", "content": prompt}],
                "temperature": 0.1
            }
            
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=data
            )
            
            if response.status_code == 200:
                result = response.json()
                # Extract and parse JSON from response
                content = result["choices"][0]["message"]["content"].strip()
                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    # Fallback if response isn't proper JSON
                    return self._extract_result_from_text(content)
            else:
                print(f"API error: {response.status_code} - {response.text}")
                return self._fallback_analysis()
                
        except Exception as e:
            print(f"Error querying OpenAI: {str(e)}")
            return self._fallback_analysis()
    
    def _query_anthropic(self, prompt):
        """Query Anthropic API"""
        try:
            if not self.api_key:
                return self._fallback_analysis()
                
            headers = {
                "x-api-key": self.api_key,
                "Content-Type": "application/json"
            }
            
            data = {
                "prompt": f"\n\nHuman: {prompt}\n\nAssistant:",
                "model": "claude-2.0",
                "max_tokens_to_sample": 1000,
                "temperature": 0.1
            }
            
            response = requests.post(
                "https://api.anthropic.com/v1/complete",
                headers=headers,
                json=data
            )
            
            if response.status_code == 200:
                result = response.json()
                content = result["completion"].strip()
                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    return self._extract_result_from_text(content)
            else:
                print(f"API error: {response.status_code} - {response.text}")
                return self._fallback_analysis()
                
        except Exception as e:
            print(f"Error querying Anthropic: {str(e)}")
            return self._fallback_analysis()
    
    def _extract_result_from_text(self, text):
        """Extract results from text if JSON parsing fails"""
        is_phishing = "phishing" in text.lower() and "not phishing" not in text.lower()
        
        return {
            "is_phishing": is_phishing,
            "confidence": 0.7 if is_phishing else 0.3,
            "techniques_detected": ["unknown"],
            "reasoning": text[:500],
            "score": 0.7 if is_phishing else 0.3
        }
    
    def _fallback_analysis(self):
        """Provide fallback analysis when API calls fail"""
        return {
            "is_phishing": False,
            "confidence": 0.5,
            "techniques_detected": [],
            "reasoning": "Unable to perform LLM analysis. Falling back to rule-based detection.",
            "score": 0.5
        }