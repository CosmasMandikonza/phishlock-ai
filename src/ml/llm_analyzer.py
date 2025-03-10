import os
from langchain.llms import OpenAI
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
from dotenv import load_dotenv

load_dotenv()

class PhishingAnalyzer:
    def __init__(self):
        self.llm = OpenAI(temperature=0)
        self.prompt = PromptTemplate(
            input_variables=["content", "sender", "subject", "urls"],
            template="""
            Analyze the following email or message for potential phishing:
            
            From: {sender}
            Subject: {subject}
            URLs in message: {urls}
            
            Message content:
            {content}
            
            Is this message likely a phishing attempt? Analyze step by step:
            1. Check if the sender address matches legitimate patterns
            2. Look for urgency or threatening language
            3. Examine for requests for sensitive information
            4. Assess if URLs are suspicious
            5. Check for grammatical errors or unusual formatting
            
            Then provide:
            - Is this message suspicious (Yes/No)
            - Confidence level (0.0 to 1.0)
            - List of specific reasons why it is or isn't suspicious
            Format as JSON with keys: is_suspicious (boolean), confidence (float), reasons (list of strings)
            """
        )
        self.chain = LLMChain(llm=self.llm, prompt=self.prompt)
        
    def analyze(self, content, sender, subject="", urls=None):
        if urls is None:
            urls = []
            
        result = self.chain.run(
            content=content,
            sender=sender,
            subject=subject,
            urls=", ".join(urls) if urls else "None"
        )
        
        # Basic parsing of the LLM response
        # In a real implementation, we'd parse the JSON properly
        # This is simplified for the hackathon
        if "true" in result.lower():
            return {
                "is_suspicious": True,
                "confidence": 0.8,  # Simplified
                "reasons": ["Suspicious content detected by LLM"]
            }
        else:
            return {
                "is_suspicious": False,
                "confidence": 0.2,  # Simplified
                "reasons": ["No suspicious patterns detected"]
            }