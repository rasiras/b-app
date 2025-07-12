from typing import Dict, List, Any
import json
import logging
from .base import BaseScanner, OutputParser
from core.config import settings

logger = logging.getLogger(__name__)

class NucleiScanner(BaseScanner):
    """Vulnerability scanning using Nuclei"""
    
    def __init__(self, tool_path: str = None):
        super().__init__(tool_path or settings.NUCLEI_PATH)
    
    def scan(self, targets: List[str], options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run nuclei vulnerability scan"""
        if not targets:
            return {"error": "No targets provided", "results": []}
        
        options = options or {}
        
        # Create temporary file with targets
        targets_str = '\n'.join(targets)
        temp_file = self.create_temp_file(targets_str)
        
        try:
            # Build command
            command = [
                self.tool_path,
                "-l", temp_file,
                "-json",
                "-silent",
                "-no-color"
            ]
            
            # Add severity filter
            if options.get("severity"):
                command.extend(["-severity", options["severity"]])
            else:
                command.extend(["-severity", "critical,high,medium,low"])
            
            # Add tags filter
            if options.get("tags"):
                command.extend(["-tags", options["tags"]])
            
            # Add exclude tags
            if options.get("exclude_tags"):
                command.extend(["-exclude-tags", options["exclude_tags"]])
            
            # Add template directory
            if options.get("templates"):
                command.extend(["-t", options["templates"]])
            
            # Add rate limiting
            if options.get("rate_limit"):
                command.extend(["-rate-limit", str(options["rate_limit"])])
            else:
                command.extend(["-rate-limit", "50"])
            
            # Add timeout
            if options.get("timeout"):
                command.extend(["-timeout", str(options["timeout"])])
            
            # Add concurrent threads
            if options.get("threads"):
                command.extend(["-c", str(options["threads"])])
            
            # Add bulk size
            if options.get("bulk_size"):
                command.extend(["-bulk-size", str(options["bulk_size"])])
            
            result = self.run_command(command, timeout=options.get("scan_timeout", 3600))
            
            if result.returncode != 0:
                error_msg = f"Nuclei scan failed: {result.stderr}"
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
            error_msg = f"Nuclei scan error: {str(e)}"
            logger.error(error_msg)
            self.errors.append(error_msg)
            return {"error": error_msg, "results": []}
        
        finally:
            self.cleanup_temp_file(temp_file)
    
    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse nuclei JSON output"""
        results = []
        
        for line in output.strip().split('\n'):
            if line.strip():
                try:
                    data = json.loads(line)
                    
                    # Extract vulnerability information
                    info = data.get("info", {})
                    
                    result = {
                        "template_id": data.get("template-id", ""),
                        "template_path": data.get("template-path", ""),
                        "matched_at": data.get("matched-at", ""),
                        "host": data.get("host", ""),
                        "type": data.get("type", ""),
                        "severity": info.get("severity", "unknown"),
                        "name": info.get("name", ""),
                        "description": info.get("description", ""),
                        "reference": info.get("reference", []),
                        "classification": info.get("classification", {}),
                        "tags": info.get("tags", []),
                        "author": info.get("author", []),
                        "timestamp": data.get("timestamp", ""),
                        "matcher_status": data.get("matcher-status", False),
                        "matcher_name": data.get("matcher-name", ""),
                        "extracted_results": data.get("extracted-results", []),
                        "request": data.get("request", ""),
                        "response": data.get("response", ""),
                        "curl_command": data.get("curl-command", ""),
                        "ip": data.get("ip", ""),
                        "port": data.get("port", "")
                    }
                    
                    # Add CVE information if available
                    classification = result.get("classification", {})
                    if classification.get("cve-id"):
                        result["cve_id"] = classification["cve-id"]
                    
                    if classification.get("cvss-score"):
                        result["cvss_score"] = classification["cvss-score"]
                    
                    if classification.get("cvss-metrics"):
                        result["cvss_metrics"] = classification["cvss-metrics"]
                    
                    results.append(result)
                    
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse Nuclei output: {line}, error: {e}")
        
        return results
    
    def get_scan_summary(self) -> Dict[str, Any]:
        """Get enhanced scan summary with vulnerability statistics"""
        base_summary = super().get_scan_summary()
        
        if self.results:
            # Count vulnerabilities by severity
            severity_counts = {}
            for result in self.results:
                severity = result.get("severity", "unknown")
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Count unique templates
            templates = set(result.get("template_id", "") for result in self.results)
            
            # Count unique hosts
            hosts = set(result.get("host", "") for result in self.results)
            
            # Get top vulnerabilities
            template_counts = {}
            for result in self.results:
                template_id = result.get("template_id", "")
                if template_id:
                    template_counts[template_id] = template_counts.get(template_id, 0) + 1
            
            top_vulnerabilities = sorted(
                template_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
            
            base_summary.update({
                "severity_breakdown": severity_counts,
                "unique_templates": len(templates),
                "unique_hosts": len(hosts),
                "top_vulnerabilities": top_vulnerabilities,
                "critical_count": severity_counts.get("critical", 0),
                "high_count": severity_counts.get("high", 0),
                "medium_count": severity_counts.get("medium", 0),
                "low_count": severity_counts.get("low", 0),
                "info_count": severity_counts.get("info", 0)
            })
        
        return base_summary

class TechStackScanner:
    """Technology stack detection using various methods"""
    
    def __init__(self):
        self.wappalyzer_patterns = self._load_wappalyzer_patterns()
    
    def _load_wappalyzer_patterns(self) -> Dict[str, Any]:
        """Load Wappalyzer patterns for technology detection"""
        # This would normally load from Wappalyzer's technologies.json
        # For now, we'll use a simplified version
        return {
            "Apache": {
                "headers": {"Server": "Apache"},
                "categories": ["Web servers"]
            },
            "Nginx": {
                "headers": {"Server": "nginx"},
                "categories": ["Web servers"]
            },
            "PHP": {
                "headers": {"X-Powered-By": "PHP"},
                "categories": ["Programming languages"]
            },
            "WordPress": {
                "html": ["wp-content", "wp-includes"],
                "categories": ["CMS"]
            },
            "Drupal": {
                "html": ["Drupal.settings"],
                "categories": ["CMS"]
            },
            "Joomla": {
                "html": ["Joomla!"],
                "categories": ["CMS"]
            },
            "React": {
                "html": ["react", "data-reactroot"],
                "categories": ["JavaScript frameworks"]
            },
            "Angular": {
                "html": ["ng-app", "ng-version"],
                "categories": ["JavaScript frameworks"]
            },
            "Vue.js": {
                "html": ["vue.js", "data-v-"],
                "categories": ["JavaScript frameworks"]
            },
            "jQuery": {
                "html": ["jquery"],
                "categories": ["JavaScript libraries"]
            }
        }
    
    def detect_from_response(self, url: str, headers: Dict[str, str], 
                           html_content: str) -> List[Dict[str, Any]]:
        """Detect technologies from HTTP response"""
        detected = []
        
        for tech_name, patterns in self.wappalyzer_patterns.items():
            confidence = 0
            
            # Check headers
            if "headers" in patterns:
                for header_name, header_pattern in patterns["headers"].items():
                    if header_name in headers:
                        if header_pattern.lower() in headers[header_name].lower():
                            confidence += 50
            
            # Check HTML content
            if "html" in patterns:
                for html_pattern in patterns["html"]:
                    if html_pattern.lower() in html_content.lower():
                        confidence += 30
            
            # Check cookies
            if "cookies" in patterns:
                cookie_header = headers.get("Set-Cookie", "")
                for cookie_pattern in patterns["cookies"]:
                    if cookie_pattern.lower() in cookie_header.lower():
                        confidence += 40
            
            if confidence > 0:
                detected.append({
                    "technology": tech_name,
                    "confidence": min(confidence, 100),
                    "categories": patterns.get("categories", []),
                    "version": "",  # Version detection would need more sophisticated patterns
                    "source": "wappalyzer"
                })
        
        return detected

class CombinedVulnScanner:
    """Combined vulnerability and technology scanning"""
    
    def __init__(self):
        self.nuclei_scanner = None
        self.tech_scanner = TechStackScanner()
        
        # Initialize Nuclei scanner
        try:
            nuclei = NucleiScanner()
            if nuclei.check_tool_availability():
                self.nuclei_scanner = nuclei
            else:
                logger.warning("Nuclei not available")
        except Exception as e:
            logger.warning(f"Failed to initialize Nuclei: {e}")
    
    def scan(self, targets: List[str], options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run combined vulnerability and technology scan"""
        options = options or {}
        results = {
            "vulnerabilities": {"results": [], "errors": []},
            "technologies": {"results": [], "errors": []},
            "summary": {}
        }
        
        # Run vulnerability scan
        if self.nuclei_scanner:
            try:
                vuln_result = self.nuclei_scanner.scan(targets, options)
                if vuln_result.get("success"):
                    results["vulnerabilities"]["results"] = vuln_result.get("results", [])
                    results["vulnerabilities"]["summary"] = vuln_result.get("summary", {})
                else:
                    results["vulnerabilities"]["errors"].append(vuln_result.get("error", "Unknown error"))
            except Exception as e:
                results["vulnerabilities"]["errors"].append(f"Vulnerability scan error: {str(e)}")
        
        # Technology detection would typically be done as part of HTTP scanning
        # For now, we'll extract tech info from vulnerability results
        tech_info = {}
        for vuln in results["vulnerabilities"]["results"]:
            host = vuln.get("host", "")
            if host and host not in tech_info:
                tech_info[host] = {
                    "host": host,
                    "technologies": [],
                    "server": "",
                    "cms": "",
                    "frameworks": []
                }
            
            # Extract technology info from vulnerability tags
            tags = vuln.get("tags", [])
            for tag in tags:
                if tag in ["apache", "nginx", "iis"]:
                    tech_info[host]["server"] = tag
                elif tag in ["wordpress", "drupal", "joomla"]:
                    tech_info[host]["cms"] = tag
                elif tag in ["php", "asp", "jsp", "python"]:
                    tech_info[host]["frameworks"].append(tag)
        
        results["technologies"]["results"] = list(tech_info.values())
        
        # Generate summary
        total_vulnerabilities = len(results["vulnerabilities"]["results"])
        total_technologies = len(results["technologies"]["results"])
        
        # Count by severity
        severity_counts = {}
        for vuln in results["vulnerabilities"]["results"]:
            severity = vuln.get("severity", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        results["summary"] = {
            "total_vulnerabilities": total_vulnerabilities,
            "total_technologies": total_technologies,
            "severity_breakdown": severity_counts,
            "unique_hosts": len(set(v.get("host", "") for v in results["vulnerabilities"]["results"])),
            "critical_vulnerabilities": severity_counts.get("critical", 0),
            "high_vulnerabilities": severity_counts.get("high", 0)
        }
        
        return results