from typing import Dict, List, Any
import json
import logging
from .base import BaseScanner, OutputParser
from core.config import settings

logger = logging.getLogger(__name__)

class SubfinderScanner(BaseScanner):
    """Subdomain enumeration using Subfinder"""
    
    def __init__(self, tool_path: str = None):
        super().__init__(tool_path or settings.SUBFINDER_PATH)
    
    def scan(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run subfinder scan"""
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")
        
        options = options or {}
        
        # Build command
        command = [
            self.tool_path,
            "-d", target,
            "-silent",
            "-json"
        ]
        
        # Add additional options
        if options.get("use_all_sources"):
            command.append("-all")
        
        if options.get("recursive"):
            command.extend(["-recursive"])
        
        if options.get("timeout"):
            command.extend(["-timeout", str(options["timeout"])])
        
        try:
            result = self.run_command(command, timeout=options.get("timeout", 1800))
            
            if result.returncode != 0:
                error_msg = f"Subfinder scan failed: {result.stderr}"
                logger.error(error_msg)
                self.errors.append(error_msg)
                return {"error": error_msg, "results": []}
            
            # Parse results
            self.results = self.parse_output(result.stdout)
            
            return {
                "success": True,
                "results": self.results,
                "summary": self.get_scan_summary()
            }
            
        except Exception as e:
            error_msg = f"Subfinder scan error: {str(e)}"
            logger.error(error_msg)
            self.errors.append(error_msg)
            return {"error": error_msg, "results": []}
    
    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse subfinder JSON output"""
        results = []
        
        for line in output.strip().split('\n'):
            if line.strip():
                try:
                    data = json.loads(line)
                    results.append({
                        "subdomain": data.get("host", ""),
                        "source": data.get("source", ["subfinder"]),
                        "ip": data.get("ip", ""),
                        "timestamp": data.get("timestamp", "")
                    })
                except json.JSONDecodeError:
                    # Handle plain text output
                    if line.strip():
                        results.append({
                            "subdomain": line.strip(),
                            "source": ["subfinder"],
                            "ip": "",
                            "timestamp": ""
                        })
        
        return results

class AmassScanner(BaseScanner):
    """Subdomain enumeration using Amass"""
    
    def __init__(self, tool_path: str = None):
        super().__init__(tool_path or settings.AMASS_PATH)
    
    def scan(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run amass scan"""
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")
        
        options = options or {}
        
        # Build command
        command = [
            self.tool_path,
            "enum",
            "-d", target,
            "-json"
        ]
        
        # Add additional options
        if options.get("passive"):
            command.append("-passive")
        
        if options.get("active"):
            command.append("-active")
        
        if options.get("timeout"):
            command.extend(["-timeout", str(options["timeout"])])
        
        try:
            result = self.run_command(command, timeout=options.get("timeout", 3600))
            
            if result.returncode != 0:
                error_msg = f"Amass scan failed: {result.stderr}"
                logger.error(error_msg)
                self.errors.append(error_msg)
                return {"error": error_msg, "results": []}
            
            # Parse results
            self.results = self.parse_output(result.stdout)
            
            return {
                "success": True,
                "results": self.results,
                "summary": self.get_scan_summary()
            }
            
        except Exception as e:
            error_msg = f"Amass scan error: {str(e)}"
            logger.error(error_msg)
            self.errors.append(error_msg)
            return {"error": error_msg, "results": []}
    
    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse amass JSON output"""
        results = []
        
        for line in output.strip().split('\n'):
            if line.strip():
                try:
                    data = json.loads(line)
                    results.append({
                        "subdomain": data.get("name", ""),
                        "source": data.get("source", ["amass"]),
                        "ip": data.get("addr", ""),
                        "timestamp": data.get("timestamp", "")
                    })
                except json.JSONDecodeError:
                    # Handle plain text output
                    if line.strip():
                        results.append({
                            "subdomain": line.strip(),
                            "source": ["amass"],
                            "ip": "",
                            "timestamp": ""
                        })
        
        return results

class CombinedSubdomainScanner:
    """Combined subdomain enumeration using multiple tools"""
    
    def __init__(self):
        self.scanners = []
        
        # Initialize available scanners
        try:
            subfinder = SubfinderScanner()
            if subfinder.check_tool_availability():
                self.scanners.append(subfinder)
            else:
                logger.warning("Subfinder not available")
        except Exception as e:
            logger.warning(f"Failed to initialize Subfinder: {e}")
        
        try:
            amass = AmassScanner()
            if amass.check_tool_availability():
                self.scanners.append(amass)
            else:
                logger.warning("Amass not available")
        except Exception as e:
            logger.warning(f"Failed to initialize Amass: {e}")
    
    def scan(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run combined subdomain scan"""
        options = options or {}
        all_results = []
        errors = []
        
        if not self.scanners:
            return {"error": "No subdomain scanners available", "results": []}
        
        # Run each scanner
        for scanner in self.scanners:
            try:
                result = scanner.scan(target, options)
                if result.get("success"):
                    all_results.extend(result.get("results", []))
                else:
                    errors.append(result.get("error", "Unknown error"))
            except Exception as e:
                errors.append(f"{scanner.__class__.__name__} error: {str(e)}")
        
        # Deduplicate results
        unique_subdomains = {}
        for result in all_results:
            subdomain = result["subdomain"]
            if subdomain not in unique_subdomains:
                unique_subdomains[subdomain] = result
            else:
                # Merge sources
                existing = unique_subdomains[subdomain]
                existing_sources = existing.get("source", [])
                new_sources = result.get("source", [])
                merged_sources = list(set(existing_sources + new_sources))
                unique_subdomains[subdomain]["source"] = merged_sources
                
                # Update IP if not present
                if not existing.get("ip") and result.get("ip"):
                    unique_subdomains[subdomain]["ip"] = result["ip"]
        
        final_results = list(unique_subdomains.values())
        
        return {
            "success": True,
            "results": final_results,
            "total_subdomains": len(final_results),
            "errors": errors,
            "scanners_used": [scanner.__class__.__name__ for scanner in self.scanners]
        }