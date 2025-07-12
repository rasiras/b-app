from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
import subprocess
import json
import logging
import tempfile
import os
from pathlib import Path
from datetime import datetime
from core.config import settings

logger = logging.getLogger(__name__)

class BaseScannerError(Exception):
    """Base exception for scanner errors"""
    pass

class ScannerNotFoundError(BaseScannerError):
    """Raised when scanner binary is not found"""
    pass

class ScannerTimeoutError(BaseScannerError):
    """Raised when scanner times out"""
    pass

class BaseScanner(ABC):
    """Base class for all scanners"""
    
    def __init__(self, tool_path: str = None):
        self.tool_path = tool_path
        self.results = []
        self.errors = []
        self.start_time = None
        self.end_time = None
        
    @abstractmethod
    def scan(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run the scan and return results"""
        pass
    
    @abstractmethod
    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse scanner output into structured data"""
        pass
    
    def check_tool_availability(self) -> bool:
        """Check if the scanner tool is available"""
        try:
            result = subprocess.run(
                [self.tool_path, "--help"],
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode == 0 or "help" in result.stdout.lower()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def run_command(self, command: List[str], timeout: int = 3600) -> subprocess.CompletedProcess:
        """Run a command and return the result"""
        try:
            logger.info(f"Running command: {' '.join(command)}")
            self.start_time = datetime.now()
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            self.end_time = datetime.now()
            logger.info(f"Command completed in {(self.end_time - self.start_time).total_seconds():.2f} seconds")
            
            return result
            
        except subprocess.TimeoutExpired:
            self.end_time = datetime.now()
            logger.error(f"Command timed out after {timeout} seconds")
            raise ScannerTimeoutError(f"Scanner timed out after {timeout} seconds")
        except FileNotFoundError:
            logger.error(f"Scanner binary not found: {command[0]}")
            raise ScannerNotFoundError(f"Scanner binary not found: {command[0]}")
        except Exception as e:
            self.end_time = datetime.now()
            logger.error(f"Error running command: {e}")
            raise BaseScannerError(f"Error running scanner: {e}")
    
    def save_results(self, results: List[Dict[str, Any]], output_file: str = None) -> str:
        """Save scan results to file"""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(
                settings.SCAN_RESULTS_DIR,
                f"{self.__class__.__name__.lower()}_{timestamp}.json"
            )
        
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        logger.info(f"Results saved to {output_file}")
        return output_file
    
    def validate_target(self, target: str) -> bool:
        """Validate target format"""
        # Basic validation - can be extended by subclasses
        return bool(target and target.strip())
    
    def get_scan_summary(self) -> Dict[str, Any]:
        """Get scan summary information"""
        duration = None
        if self.start_time and self.end_time:
            duration = (self.end_time - self.start_time).total_seconds()
        
        return {
            "scanner": self.__class__.__name__,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": duration,
            "results_count": len(self.results),
            "errors_count": len(self.errors),
            "errors": self.errors
        }
    
    def create_temp_file(self, content: str, suffix: str = ".txt") -> str:
        """Create a temporary file with content"""
        with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
            f.write(content)
            return f.name
    
    def cleanup_temp_file(self, filepath: str):
        """Clean up temporary file"""
        try:
            os.unlink(filepath)
        except OSError:
            pass

class OutputParser:
    """Utility class for parsing scanner outputs"""
    
    @staticmethod
    def parse_json_lines(output: str) -> List[Dict[str, Any]]:
        """Parse JSON lines output"""
        results = []
        for line in output.strip().split('\n'):
            if line.strip():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse JSON line: {line}, error: {e}")
        return results
    
    @staticmethod
    def parse_newline_separated(output: str) -> List[str]:
        """Parse newline separated output"""
        return [line.strip() for line in output.strip().split('\n') if line.strip()]
    
    @staticmethod
    def extract_domains(text: str) -> List[str]:
        """Extract domain names from text"""
        import re
        domain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
        return list(set(re.findall(domain_pattern, text)))
    
    @staticmethod
    def extract_ips(text: str) -> List[str]:
        """Extract IP addresses from text"""
        import re
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        return list(set(re.findall(ip_pattern, text)))
    
    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """Extract URLs from text"""
        import re
        url_pattern = r'https?://(?:[-\w.])+(?::[0-9]+)?(?:/(?:[\w/_.])*)?(?:\?(?:[\w&=%.-])*)?(?:#(?:[\w.-])*)?'
        return list(set(re.findall(url_pattern, text)))