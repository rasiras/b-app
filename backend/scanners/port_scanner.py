from typing import Dict, List, Any
import json
import logging
from .base import BaseScanner, OutputParser
from core.config import settings

logger = logging.getLogger(__name__)

class NaabuScanner(BaseScanner):
    """Port scanning using Naabu"""
    
    def __init__(self, tool_path: str = None):
        super().__init__(tool_path or settings.NAABU_PATH)
    
    def scan(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run naabu port scan"""
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")
        
        options = options or {}
        
        # Build command
        command = [
            self.tool_path,
            "-host", target,
            "-json",
            "-silent"
        ]
        
        # Add port range
        if options.get("ports"):
            command.extend(["-p", options["ports"]])
        elif options.get("top_ports"):
            command.extend(["-top-ports", str(options["top_ports"])])
        else:
            command.extend(["-p", "1-10000"])  # Default port range
        
        # Add scan options
        if options.get("rate"):
            command.extend(["-rate", str(options["rate"])])
        
        if options.get("timeout"):
            command.extend(["-timeout", str(options["timeout"])])
        
        try:
            result = self.run_command(command, timeout=options.get("timeout", 1800))
            
            if result.returncode != 0:
                error_msg = f"Naabu scan failed: {result.stderr}"
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
            error_msg = f"Naabu scan error: {str(e)}"
            logger.error(error_msg)
            self.errors.append(error_msg)
            return {"error": error_msg, "results": []}
    
    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse naabu JSON output"""
        results = []
        
        for line in output.strip().split('\n'):
            if line.strip():
                try:
                    data = json.loads(line)
                    results.append({
                        "host": data.get("host", ""),
                        "port": data.get("port", 0),
                        "protocol": data.get("protocol", "tcp"),
                        "service": "",
                        "version": "",
                        "banner": ""
                    })
                except json.JSONDecodeError:
                    # Handle plain text output (host:port format)
                    if ":" in line:
                        parts = line.strip().split(":")
                        if len(parts) >= 2:
                            results.append({
                                "host": parts[0],
                                "port": int(parts[1]),
                                "protocol": "tcp",
                                "service": "",
                                "version": "",
                                "banner": ""
                            })
        
        return results

class HTTPXScanner(BaseScanner):
    """HTTP service detection using HTTPX"""
    
    def __init__(self, tool_path: str = None):
        super().__init__(tool_path or settings.HTTPX_PATH)
    
    def scan(self, targets: List[str], options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run httpx scan on list of targets"""
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
                "-title",
                "-status-code",
                "-content-length",
                "-tech-detect"
            ]
            
            # Add additional options
            if options.get("timeout"):
                command.extend(["-timeout", str(options["timeout"])])
            
            if options.get("follow_redirects"):
                command.append("-follow-redirects")
            
            if options.get("threads"):
                command.extend(["-threads", str(options["threads"])])
            
            result = self.run_command(command, timeout=options.get("timeout", 1800))
            
            if result.returncode != 0:
                error_msg = f"HTTPX scan failed: {result.stderr}"
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
            error_msg = f"HTTPX scan error: {str(e)}"
            logger.error(error_msg)
            self.errors.append(error_msg)
            return {"error": error_msg, "results": []}
        
        finally:
            self.cleanup_temp_file(temp_file)
    
    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse httpx JSON output"""
        results = []
        
        for line in output.strip().split('\n'):
            if line.strip():
                try:
                    data = json.loads(line)
                    results.append({
                        "url": data.get("url", ""),
                        "host": data.get("host", ""),
                        "port": data.get("port", 80),
                        "scheme": data.get("scheme", "http"),
                        "title": data.get("title", ""),
                        "status_code": data.get("status_code", 0),
                        "content_length": data.get("content_length", 0),
                        "technologies": data.get("technologies", []),
                        "server": data.get("server", ""),
                        "response_time": data.get("response_time", "")
                    })
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse HTTPX output: {line}")
        
        return results

class CombinedPortScanner:
    """Combined port and service scanning"""
    
    def __init__(self):
        self.port_scanner = None
        self.http_scanner = None
        
        # Initialize port scanner
        try:
            naabu = NaabuScanner()
            if naabu.check_tool_availability():
                self.port_scanner = naabu
            else:
                logger.warning("Naabu not available")
        except Exception as e:
            logger.warning(f"Failed to initialize Naabu: {e}")
        
        # Initialize HTTP scanner
        try:
            httpx = HTTPXScanner()
            if httpx.check_tool_availability():
                self.http_scanner = httpx
            else:
                logger.warning("HTTPX not available")
        except Exception as e:
            logger.warning(f"Failed to initialize HTTPX: {e}")
    
    def scan(self, targets: List[str], options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run combined port and service scan"""
        options = options or {}
        results = {
            "port_scan": {"results": [], "errors": []},
            "http_scan": {"results": [], "errors": []},
            "summary": {}
        }
        
        # Run port scan on each target
        if self.port_scanner:
            for target in targets:
                try:
                    port_result = self.port_scanner.scan(target, options)
                    if port_result.get("success"):
                        results["port_scan"]["results"].extend(port_result.get("results", []))
                    else:
                        results["port_scan"]["errors"].append(port_result.get("error", "Unknown error"))
                except Exception as e:
                    results["port_scan"]["errors"].append(f"Port scan error for {target}: {str(e)}")
        
        # Run HTTP scan on targets
        if self.http_scanner:
            # Create HTTP targets from original targets
            http_targets = []
            for target in targets:
                http_targets.extend([f"http://{target}", f"https://{target}"])
            
            # Also add specific ports from port scan results
            for port_result in results["port_scan"]["results"]:
                if port_result.get("port") in [80, 443, 8080, 8443, 3000, 5000, 8000, 9000]:
                    host = port_result.get("host", "")
                    port = port_result.get("port", 80)
                    if port in [443, 8443]:
                        http_targets.append(f"https://{host}:{port}")
                    else:
                        http_targets.append(f"http://{host}:{port}")
            
            if http_targets:
                try:
                    http_result = self.http_scanner.scan(http_targets, options)
                    if http_result.get("success"):
                        results["http_scan"]["results"] = http_result.get("results", [])
                    else:
                        results["http_scan"]["errors"].append(http_result.get("error", "Unknown error"))
                except Exception as e:
                    results["http_scan"]["errors"].append(f"HTTP scan error: {str(e)}")
        
        # Generate summary
        total_ports = len(results["port_scan"]["results"])
        total_http_services = len(results["http_scan"]["results"])
        
        results["summary"] = {
            "total_open_ports": total_ports,
            "total_http_services": total_http_services,
            "unique_hosts": len(set(r.get("host", "") for r in results["port_scan"]["results"])),
            "common_ports": self._get_common_ports(results["port_scan"]["results"]),
            "technologies_found": self._get_technologies(results["http_scan"]["results"])
        }
        
        return results
    
    def _get_common_ports(self, port_results: List[Dict[str, Any]]) -> Dict[int, int]:
        """Get count of common ports"""
        port_counts = {}
        for result in port_results:
            port = result.get("port", 0)
            port_counts[port] = port_counts.get(port, 0) + 1
        
        # Return top 10 most common ports
        return dict(sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10])
    
    def _get_technologies(self, http_results: List[Dict[str, Any]]) -> List[str]:
        """Get unique technologies found"""
        technologies = set()
        for result in http_results:
            techs = result.get("technologies", [])
            technologies.update(techs)
        
        return sorted(list(technologies))