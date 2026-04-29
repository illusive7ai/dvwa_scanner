"""
core/finding.py - Finding data model and scan results container
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime


@dataclass
class Finding:
    """
    Represents a single confirmed vulnerability finding.
    """
    # Identity
    title: str
    vulnerability_type: str       # e.g. "SQL Injection (Time-Based)"

    # OWASP / classification
    owasp_category: str           # e.g. "A03"
    owasp_name: str               # e.g. "Injection"
    cwe_id: Optional[str] = None  # e.g. "CWE-89"

    # Severity
    severity: str = "Medium"      # Critical | High | Medium | Low | Informational
    cvss_score: float = 0.0
    cvss_vector: str = ""

    # Target
    url: str = ""
    method: str = "GET"
    parameter: str = ""
    payload: str = ""

    # Evidence
    description: str = ""
    proof: str = ""               # Request/response snippet
    request_snippet: str = ""
    response_snippet: str = ""

    # Remediation
    remediation: str = ""
    references: List[str] = field(default_factory=list)

    # Metadata
    module: str = ""
    confidence: str = "High"      # High | Medium | Low
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "vulnerability_type": self.vulnerability_type,
            "owasp_category": self.owasp_category,
            "owasp_name": self.owasp_name,
            "cwe_id": self.cwe_id,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "url": self.url,
            "method": self.method,
            "parameter": self.parameter,
            "payload": self.payload,
            "description": self.description,
            "proof": self.proof,
            "request_snippet": self.request_snippet,
            "response_snippet": self.response_snippet,
            "remediation": self.remediation,
            "references": self.references,
            "module": self.module,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
        }


@dataclass
class ScanResults:
    """
    Container for all scan output.
    """
    target_url: str
    start_time: str
    end_time: str = ""
    scanner_version: str = "1.0.0"
    modules_run: List[str] = field(default_factory=list)
    findings: List[Dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)

    def add_finding(self, finding: Finding):
        self.findings.append(finding.to_dict())

    def add_findings(self, findings: List[Finding]):
        for f in findings:
            self.add_finding(f)

    def summary(self) -> Dict[str, int]:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for f in self.findings:
            sev = f.get("severity", "Informational")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_metadata": {
                "target_url": self.target_url,
                "start_time": self.start_time,
                "end_time": self.end_time,
                "scanner_version": self.scanner_version,
                "modules_run": self.modules_run,
            },
            "summary": self.summary(),
            "total_findings": len(self.findings),
            "findings": self.findings,
            "errors": self.errors,
            "stats": self.stats,
        }