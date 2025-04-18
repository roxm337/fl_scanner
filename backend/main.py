from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import subprocess
import shlex
import re
import json
from typing import Dict, List, Optional, Any
import xml.etree.ElementTree as ET

app = FastAPI(title="Advanced Vulnerability Scanner API")

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    target: str
    options: str = "-sV"

class VulnerabilityScanRequest(BaseModel):
    target: str
    scan_level: int = 2
    enable_script_scan: bool = False
    enable_os_scan: bool = False
    enable_version_detection: bool = True

class ScanResponse(BaseModel):
    results: str

class Vulnerability(BaseModel):
    name: str
    severity: str
    description: str
    solution: Optional[str] = None
    references: List[str] = []

@app.post("/scan", response_model=ScanResponse)
async def run_scan(request: ScanRequest):
    # Validate the target input (basic validation)
    target = request.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target is required")
    
    # Validate and sanitize options to prevent command injection
    options = request.options.strip()
    
    # Build the command - be careful to properly escape arguments
    cmd = f"nmap {options} {shlex.quote(target)}"
    
    try:
        # Run the nmap command
        process = subprocess.run(
            cmd,
            shell=True,  # Use shell=True with caution and proper input sanitization
            capture_output=True,
            text=True,
            timeout=60  # Limit scan time to 60 seconds
        )
        
        # Return the results
        return ScanResponse(results=process.stdout if process.stdout else process.stderr)
    
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Scan timed out")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error running scan: {str(e)}")

@app.post("/vulnerability_scan", response_model=ScanResponse)
async def run_vulnerability_scan(request: VulnerabilityScanRequest):
    target = request.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target is required")
    
    # Build nmap command based on scan level and options
    options = []
    
    # Set timing template based on scan level (T0-T5)
    timing_template = min(request.scan_level - 1, 5)  # Convert level 1-5 to T0-T4
    options.append(f"-T{timing_template}")
    
    # Add port range based on scan level
    if request.scan_level == 1:
        options.append("-F")  # Fast scan mode - fewer ports
    elif request.scan_level == 5:
        options.append("-p-")  # All ports
    else:
        options.append("-p 1-1000")  # Default range
    
    # Add optional scan types
    if request.enable_version_detection:
        options.append("-sV")
    
    if request.enable_os_scan:
        options.append("-O")
    
    # Always use XML output for parsing
    xml_output = "/tmp/nmap_scan_result.xml"
    options.append(f"-oX {xml_output}")
    
    # Add vulnerability scripts if requested
    script_options = []
    if request.enable_script_scan:
        script_options.append("vuln")
    
    if script_options:
        options.append(f"--script={','.join(script_options)}")
    
    # Build the command
    cmd = f"nmap {' '.join(options)} {shlex.quote(target)}"
    
    try:
        # Run the scan - this may take longer than a basic scan
        process = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300  # Allow up to 5 minutes for vulnerability scans
        )
        
        if process.returncode != 0:
            return ScanResponse(results=f"Scan error: {process.stderr}")
        
        # Parse the XML output to create a more structured vulnerability report
        vulnerabilities = []
        try:
            results_formatted = process.stdout
            
            # Parse the XML file if it exists
            try:
                tree = ET.parse(xml_output)
                root = tree.getroot()
                
                # Extract vulnerability information from NSE script output
                results_formatted = parse_nmap_xml_for_vulnerabilities(root)
            except Exception as xml_err:
                results_formatted += f"\n\nNote: XML parsing failed: {str(xml_err)}"
                
            # Include CVE database check for discovered services
            cve_info = check_known_cves(process.stdout)
            if cve_info:
                results_formatted += "\n\n--- POTENTIAL CVEs BASED ON DETECTED SERVICES ---\n"
                results_formatted += cve_info
                
            # Add remediation suggestions
            if request.enable_script_scan:
                remediation = generate_remediation_suggestions(process.stdout)
                if remediation:
                    results_formatted += "\n\n--- REMEDIATION SUGGESTIONS ---\n"
                    results_formatted += remediation
                
            return ScanResponse(results=results_formatted)
            
        except Exception as parse_err:
            return ScanResponse(results=f"{process.stdout}\n\nError parsing results: {str(parse_err)}")
    
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Vulnerability scan timed out after 5 minutes")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error running vulnerability scan: {str(e)}")

def parse_nmap_xml_for_vulnerabilities(root):
    report = []
    report.append("VULNERABILITY SCAN REPORT\n" + "="*25 + "\n")
    
    # Parse host information
    for host in root.findall(".//host"):
        # Get IP address
        ip = host.find(".//address[@addrtype='ipv4']")
        if ip is not None:
            report.append(f"Target: {ip.get('addr')}\n")
        
        # Get hostname if available
        hostname = host.find(".//hostname")
        if hostname is not None:
            report.append(f"Hostname: {hostname.get('name')}\n")
        
        # OS detection results
        os_elem = host.find(".//os")
        if os_elem is not None:
            os_matches = os_elem.findall(".//osmatch")
            if os_matches:
                report.append("\nOS DETECTION RESULTS:")
                for os_match in os_matches[:3]:  # Show top 3 OS matches
                    name = os_match.get("name", "Unknown")
                    accuracy = os_match.get("accuracy", "0")
                    report.append(f"  - {name} (Accuracy: {accuracy}%)")
        
        # Parse ports and their services
        ports = host.findall(".//port")
        if ports:
            report.append("\nOPEN PORTS AND SERVICES:")
            for port in ports:
                port_id = port.get("portid")
                protocol = port.get("protocol")
                
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    service = port.find("service")
                    service_name = service.get("name", "unknown") if service is not None else "unknown"
                    product = service.get("product", "") if service is not None else ""
                    version = service.get("version", "") if service is not None else ""
                    
                    service_info = f"  - {port_id}/{protocol}: {service_name}"
                    if product:
                        service_info += f" ({product}"
                        if version:
                            service_info += f" {version}"
                        service_info += ")"
                    
                    report.append(service_info)
        
        # Parse script outputs (vulnerabilities)
        scripts = host.findall(".//script")
        if scripts:
            vuln_found = False
            for script in scripts:
                if script.get("id", "").startswith("vuln-"):
                    if not vuln_found:
                        report.append("\nVULNERABILITIES DETECTED:")
                        vuln_found = True
                    
                    script_id = script.get("id")
                    output = script.get("output")
                    
                    # Clean up and format the output
                    if output:
                        output = re.sub(r'\n\s+', '\n    ', output)
                        report.append(f"\n  {script_id}:")
                        report.append(f"    {output}")
    
    return "\n".join(report)

def check_known_cves(scan_output):
    """
    Simple simulation of checking detected services against a CVE database.
    In a real implementation, this would query an actual CVE database or API.
    """
    cve_info = []
    
    # Example patterns to look for (in a real app, use a proper database)
    vulnerable_patterns = [
        {"pattern": r"OpenSSH\s+([0-7]\.[0-9]|8\.[0-2])", 
         "cve": "CVE-2020-15778", 
         "description": "Potential command injection vulnerability in scp"},
        {"pattern": r"Apache\s+([0-2]\.[0-9]\.[0-9]|2\.4\.[0-9]|2\.4\.([0-3][0-9]|4[0-8]))", 
         "cve": "CVE-2021-44790", 
         "description": "Apache HTTP Server: Possible buffer overflow when parsing multipart content"},
        {"pattern": r"ProFTPD\s+([0-1]\.[0-9]\.[0-9]|1\.3\.[0-6])", 
         "cve": "CVE-2020-9273", 
         "description": "Directory traversal vulnerability"},
        {"pattern": r"nginx\s+([0-1]\.[0-9]\.[0-9]|1\.1[0-7])", 
         "cve": "CVE-2019-9511", 
         "description": "HTTP/2 excessive CPU usage vulnerability"},
    ]
    
    for vuln in vulnerable_patterns:
        if re.search(vuln["pattern"], scan_output):
            cve_info.append(f"{vuln['cve']}: {vuln['description']}")
    
    return "\n".join(cve_info)

def generate_remediation_suggestions(scan_output):
    """Generate remediation suggestions based on scan output"""
    suggestions = []
    
    # Common remediation patterns (in a real app, this would be more sophisticated)
    if "OpenSSH" in scan_output:
        suggestions.append("- Update OpenSSH to the latest version to avoid known vulnerabilities")
    
    if "Apache" in scan_output:
        suggestions.append("- Update Apache HTTP Server to latest version")
        suggestions.append("- Disable unnecessary modules")
        suggestions.append("- Consider using mod_security WAF")
    
    if re.search(r"telnet|ftp", scan_output, re.IGNORECASE):
        suggestions.append("- Replace insecure protocols (Telnet, FTP) with encrypted alternatives (SSH, SFTP)")
    
    if "http" in scan_output.lower():
        suggestions.append("- Implement HTTPS with strong TLS configuration")
        suggestions.append("- Use HTTP security headers (Content-Security-Policy, X-XSS-Protection)")
    
    if "SMB" in scan_output or "Windows" in scan_output:
        suggestions.append("- Ensure SMB signing is enabled")
        suggestions.append("- Disable SMBv1 and use only SMBv3")
    
    # Generic suggestions
    suggestions.append("- Implement a firewall to restrict access to necessary services only")
    suggestions.append("- Use strong authentication mechanisms for all exposed services")
    suggestions.append("- Regularly update and patch all software")
    
    return "\n".join(suggestions)