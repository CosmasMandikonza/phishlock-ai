"""
Integrated analyzer that combines all detection methods
"""
import os
from datetime import datetime

# Import necessary components
try:
    from src.ml.behavioral_analyzer import SimpleBehavioralAnalyzer
except ImportError:
    from src.ml.behavioral_analyzer import BehavioralAnalyzer as SimpleBehavioralAnalyzer

try:
    from src.ml.url_extractor import SimpleURLExtractor
except ImportError:
    from src.ml.url_extractor import URLExtractor as SimpleURLExtractor

# Conditionally import advanced components
try:
    from src.ml.llm_analyzer import LLMAnalyzer
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False

try:
    from src.ml.rag_analyzer import RAGAnalyzer
    RAG_AVAILABLE = True
except ImportError:
    RAG_AVAILABLE = False

try:
    from src.ml.ethics_module import EthicsModule
    ETHICS_AVAILABLE = True
except ImportError:
    ETHICS_AVAILABLE = False

try:
    from src.ml.logo_detector import LogoDetector
    LOGO_AVAILABLE = True
except ImportError:
    LOGO_AVAILABLE = False

try:
    from src.ml.fabric_integration import FabricIntegration
    FABRIC_AVAILABLE = True
except ImportError:
    FABRIC_AVAILABLE = False

class IntegratedAnalyzer:
    """Combines all analysis methods for comprehensive phishing detection"""
    
    def __init__(self):
        # Always available basic analyzers
        self.behavioral_analyzer = SimpleBehavioralAnalyzer()
        self.url_extractor = SimpleURLExtractor()
        
        # Conditionally initialize advanced components
        self.llm_analyzer = LLMAnalyzer() if LLM_AVAILABLE else None
        self.rag_analyzer = RAGAnalyzer() if RAG_AVAILABLE else None
        self.ethics_module = EthicsModule() if ETHICS_AVAILABLE else None
        self.logo_detector = LogoDetector() if LOGO_AVAILABLE else None
        self.fabric_integration = FabricIntegration() if FABRIC_AVAILABLE else None
        
        # Check if fabric should be used
        self.use_fabric = FABRIC_AVAILABLE and self.fabric_integration and self.fabric_integration.available \
                          and bool(os.getenv("ENABLE_FABRIC", "false").lower() == "true")
        
        # Component weights
        self.weights = {
            "behavioral": 0.4,
            "url": 0.3,
            "llm": 0.3,
            "rag": 0.3,
            "logo": 0.2
        }
        
        # Flag indicating which components are active
        self.active_components = {
            "behavioral": True,
            "url": True,
            "llm": LLM_AVAILABLE and bool(os.getenv("ENABLE_LLM", "true").lower() == "true"),
            "rag": RAG_AVAILABLE and bool(os.getenv("ENABLE_RAG", "true").lower() == "true"),
            "logo": LOGO_AVAILABLE
        }
        
        # Adjust weights if some components are disabled
        self._normalize_weights()
    
    def _normalize_weights(self):
        """Normalize weights based on active components"""
        active_sum = sum(self.weights[k] for k, v in self.active_components.items() if v and k in self.weights)
        if active_sum == 0:
            # Fallback to behavioral only
            self.weights["behavioral"] = 1.0
            return
            
        # Normalize weights to sum to 1
        factor = 1.0 / active_sum
        for key in self.weights:
            if self.active_components.get(key, False) and key in self.weights:
                self.weights[key] *= factor
            else:
                self.weights[key] = 0
    
    def analyze_message(self, message):
        """
        Analyze a message using all available methods
        
        Args:
            message (dict): Message with sender, subject, content
            
        Returns:
            dict: Comprehensive analysis result
        """
        start_time = datetime.now()
        
        # Initialize ALL required variables
        scores = {}
        component_results = {}
        extracted_urls = []
        suspicious_domains = []
        reasons = []
        is_suspicious = False
        weighted_score = 0
        recommendation = "No specific recommendation available."
        technical_details = {"status": "initialized"}
        
        try:
            # Preliminary checks
            if not message.get("content") and not message.get("subject"):
                return {
                    "is_suspicious": False,
                    "confidence": 0,
                    "reasons": ["Empty message"],
                    "analysis_time": (datetime.now() - start_time).total_seconds()
                }
            
            # 1. Behavioral analysis
            if self.active_components["behavioral"]:
                behavioral_result = self.behavioral_analyzer.analyze_message(message)
                scores["behavioral"] = behavioral_result["combined_score"]
                component_results["behavioral"] = behavioral_result
            
            # 2. URL analysis
            if self.active_components["url"]:
                url_result = self.url_extractor.analyze_urls_in_text(message["content"])
                scores["url"] = url_result["overall_score"]
                component_results["url"] = url_result
                extracted_urls = url_result.get("urls_found", [])
            
            # 3. LLM analysis (if available)
            if self.active_components["llm"] and self.llm_analyzer:
                try:
                    llm_result = self.llm_analyzer.detect_sophisticated_phishing(message)
                    scores["llm"] = llm_result["score"]
                    component_results["llm"] = llm_result
                except Exception as e:
                    print(f"LLM analysis error: {str(e)}")
                    scores["llm"] = 0
                    component_results["llm"] = {"error": str(e)}
            
            # 4. RAG analysis (if available)
            if self.active_components["rag"] and self.rag_analyzer:
                try:
                    rag_result = self.rag_analyzer.analyze(message)
                    scores["rag"] = rag_result["phishing_score"]
                    component_results["rag"] = rag_result
                except Exception as e:
                    print(f"RAG analysis error: {str(e)}")
                    scores["rag"] = 0
                    component_results["rag"] = {"error": str(e)}
            
            # 5. Logo detection (if message has HTML content)
            if self.active_components.get("logo", False) and hasattr(self, 'logo_detector') and self.logo_detector and message.get("html_content"):
                try:
                    logo_result = self.logo_detector.analyze_html_for_brand_logos(
                        message["html_content"], 
                        message.get("source_url")
                    )
                    scores["logo"] = logo_result["impersonation_confidence"] if logo_result.get("impersonation_detected") else 0
                    component_results["logo"] = logo_result
                except Exception as e:
                    print(f"Logo detection error: {str(e)}")
                    scores["logo"] = 0
                    component_results["logo"] = {"error": str(e)}
            
            # Calculate weighted score
            weighted_score = sum(scores.get(k, 0) * self.weights.get(k, 0) 
                                for k in self.active_components 
                                if self.active_components.get(k, False))
            
            # Determine if suspicious
            is_suspicious = weighted_score > 0.5
            
            # Generate reasons for the decision
            reasons = self.generate_reasons(component_results, is_suspicious)
            
            # Generate technical details
            technical_details = {
                "component_scores": scores,
                "weights": {k: v for k, v in self.weights.items() if self.active_components.get(k, False)},
                "final_score": weighted_score,
                "active_components": self.active_components,
            }
            
            # Identify suspicious domains
            suspicious_domains = []
            for url in extracted_urls:
                # Simple domain extraction
                try:
                    domain = url.split("//")[-1].split("/")[0]
                    is_suspicious_domain = False
                    
                    # Check for suspicious TLDs
                    suspicious_tlds = ['xyz', 'top', 'club', 'online', 'site', 'icu', 'space']
                    if any(domain.endswith("." + tld) for tld in suspicious_tlds):
                        is_suspicious_domain = True
                        
                    # Check for brand impersonation
                    impersonated_brand = None
                    if "rag" in component_results and component_results["rag"].get("impersonated_brand"):
                        impersonated_brand = component_results["rag"]["impersonated_brand"]
                        
                    if is_suspicious_domain:
                        suspicious_domains.append({
                            "domain": domain,
                            "url": url,
                            "score": 0.8,
                            "indicators": ["Suspicious TLD", "Impersonation" if impersonated_brand else "Unknown"]
                        })
                except Exception as e:
                    print(f"Error analyzing domain in URL {url}: {str(e)}")
            
            # Create recommendation
            recommendation = self.generate_recommendation(is_suspicious, component_results)
            
            # Fabric analysis if available
            if self.use_fabric and hasattr(self, 'fabric_integration') and self.fabric_integration:
                try:
                    fabric_result = self.fabric_integration.analyze_phishing_with_fabric(message)
                    if not fabric_result.get("error") and fabric_result.get("result"):
                        technical_details["fabric_analysis"] = fabric_result["result"]
                        if isinstance(fabric_result["result"], dict) and fabric_result["result"].get("is_phishing"):
                            fabric_confidence = fabric_result["result"].get("confidence", 0.7)
                            weighted_score = (weighted_score + fabric_confidence) / 2
                            is_suspicious = weighted_score > 0.5
                            reasons.append("Advanced pattern analysis detected phishing indicators")
                except Exception as e:
                    print(f"Fabric analysis error: {str(e)}")
                    technical_details.setdefault("errors", []).append(f"Fabric analysis: {str(e)}")
        
        except Exception as e:
            print(f"Error in analyze_message: {str(e)}")
            # If an error occurs, return a basic result with the error info
            return {
                "is_suspicious": False,
                "confidence": 0,
                "reasons": [f"Analysis error: {str(e)}"],
                "analysis_time": (datetime.now() - start_time).total_seconds(),
                "error": str(e)
            }
        
        finally:
            # Always calculate analysis time
            analysis_time = (datetime.now() - start_time).total_seconds()
        
        # Build result dictionary
        result = {
            "is_suspicious": is_suspicious,
            "confidence": weighted_score,
            "reasons": reasons,
            "extracted_urls": extracted_urls,
            "suspicious_domains": suspicious_domains,
            "recommendation": recommendation,
            "technical_details": technical_details,
            "analysis_time": analysis_time
        }
        
        # Add impersonated brand if detected
        if "rag" in component_results and component_results["rag"].get("impersonated_brand"):
            result["impersonated_brand"] = component_results["rag"]["impersonated_brand"]
        
        # Add tactics used
        if "behavioral" in component_results:
            result["tactics_used"] = list(component_results["behavioral"].get("tactics_detected", {}).keys())
        
        # Generate explanation if ethics module is available
        if hasattr(self, 'ethics_module') and self.ethics_module:
            try:
                result["explanation"] = self.ethics_module.explain_decision(result)
            except Exception as e:
                print(f"Ethics module error: {str(e)}")
                result["explanation"] = {"error": str(e)}
        
        return result
    
    def generate_reasons(self, component_results, is_suspicious):
        """Generate human-readable reasons for the decision"""
        reasons = []
        
        # Add behavioral reasons
        if "behavioral" in component_results:
            behavioral = component_results["behavioral"]
            for tactic, details in behavioral.get("tactics_detected", {}).items():
                if tactic == "urgency":
                    reasons.append("Creates a false sense of urgency")
                elif tactic == "fear":
                    reasons.append("Uses fear tactics to manipulate")
                elif tactic == "reward":
                    reasons.append("Exploits desire for rewards or financial gain")
                elif tactic == "curiosity":
                    reasons.append("Exploits natural curiosity to encourage clicking")
                elif tactic == "authority":
                    reasons.append("Impersonates authority figures to increase compliance")
                else:
                    reasons.append(f"Uses {tactic.replace('_', ' ')} manipulation tactic")
        
        # Add URL reasons
        if "url" in component_results:
            url_result = component_results["url"]
            if url_result.get("suspicious_count", 0) > 0:
                reasons.append(f"Contains {url_result.get('suspicious_count')} suspicious URLs")
        
        # Add RAG reasons
        if "rag" in component_results:
            rag_result = component_results["rag"]
            if rag_result.get("impersonated_brand"):
                reasons.append(f"Impersonates {rag_result['impersonated_brand']}")
            if rag_result.get("tactics_identified"):
                for tactic in rag_result.get("tactics_identified", [])[:2]:  # Limit to top 2
                    reasons.append(f"Uses {tactic} manipulation tactic")
        
        # Add LLM reasons
        if "llm" in component_results:
            llm_result = component_results["llm"]
            if llm_result.get("techniques_detected"):
                for technique in llm_result.get("techniques_detected", [])[:2]:  # Limit to top 2
                    reasons.append(f"Shows patterns of {technique}")
        
        # Add logo detection reasons
        if "logo" in component_results:
            logo_result = component_results["logo"]
            if logo_result.get("impersonation_detected") and logo_result.get("impersonated_brand"):
                reasons.append(f"Found {logo_result['impersonated_brand']} logo in a suspicious domain")
        
        # If no suspicious reasons but marked suspicious
        if not reasons and is_suspicious:
            reasons.append("Combination of subtle factors indicates potential phishing")
        
        # If not suspicious and no reasons
        if not reasons and not is_suspicious:
            reasons.append("No suspicious indicators detected")
        
        return reasons
    
    def generate_recommendation(self, is_suspicious, component_results):
        """Generate a recommendation based on analysis results"""
        if not is_suspicious:
            return "This message appears legitimate, but always verify sensitive requests through official channels."
        
        # Determine the primary concern
        impersonated_brand = None
        primary_tactic = None
        
        if "rag" in component_results:
            impersonated_brand = component_results["rag"].get("impersonated_brand")
        
        if "logo" in component_results and component_results["logo"].get("impersonated_brand"):
            impersonated_brand = component_results["logo"].get("impersonated_brand")
        
        if "behavioral" in component_results and component_results["behavioral"].get("primary_tactic"):
            primary_tactic = component_results["behavioral"]["primary_tactic"]
        
        # Generate specific recommendation
        if impersonated_brand:
            return f"This message appears to be impersonating {impersonated_brand}. Do not interact with it or click any links. If you need to verify information, visit the official {impersonated_brand} website directly by typing the address in your browser."
        
        if primary_tactic == "urgency":
            return "This message uses urgency tactics to pressure you into action. Legitimate organizations rarely use these tactics. Take time to verify before responding."
        
        if primary_tactic == "fear":
            return "This message uses fear tactics to manipulate you. Contact the purported sender through official channels to verify the message's legitimacy."
        
        if "url" in component_results and component_results["url"].get("suspicious_count", 0) > 0:
            return "This message contains suspicious links. Do not click on them. If you need to visit the website, type the official address directly in your browser."
        
        # Default recommendation
        return "This message shows signs of being a phishing attempt. Exercise caution and verify through official channels before taking any action."