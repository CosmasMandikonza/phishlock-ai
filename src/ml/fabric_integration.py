# Add a new file: src/ml/fabric_integration.py
import os
import json
import subprocess
import tempfile

class FabricIntegration:
    """Integration with danielmiessler/fabric for advanced prompt patterns"""
    
    def __init__(self, fabric_path=None):
        """Initialize Fabric integration"""
        self.fabric_path = fabric_path or self._find_fabric()
        self.available = self.fabric_path is not None
        
    def _find_fabric(self):
        """Find Fabric installation"""
        try:
            # Check if fabric is installed
            result = subprocess.run(
                ["which", "fabric"],
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode == 0:
                return result.stdout.strip()
            
            # Check common paths
            common_paths = [
                "/usr/local/bin/fabric",
                "/usr/bin/fabric",
                os.path.expanduser("~/.local/bin/fabric")
            ]
            
            for path in common_paths:
                if os.path.exists(path) and os.access(path, os.X_OK):
                    return path
            
            return None
        except Exception:
            return None
    
    def analyze_phishing_with_fabric(self, message):
        """Use Fabric to analyze a potential phishing message"""
        if not self.available:
            return {"error": "Fabric not available", "result": None}
        
        # Create a temporary file with the message
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False) as f:
            message_path = f.name
            f.write(f"From: {message.get('sender', '')}\n")
            f.write(f"Subject: {message.get('subject', '')}\n\n")
            f.write(message.get('content', ''))
        
        try:
            # Run Fabric with the phishing pattern
            result = subprocess.run(
                [self.fabric_path, "run", "--pattern", "phishing_detection", "--input", message_path],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Parse the output
            output = result.stdout.strip()
            try:
                return {"result": json.loads(output), "error": None}
            except json.JSONDecodeError:
                return {"result": output, "error": None}
        except subprocess.CalledProcessError as e:
            return {"error": e.stderr, "result": None}
        finally:
            # Clean up the temporary file
            os.unlink(message_path)