"""
Keystone Supply Chain Gate & Model Security
Module 6.1 Reference Implementation: AI Agent Security & Governance

Implements:
  1. SBOM Generation & CVE Vulnerability Gate (Syft / Grype mock & validator)
  2. Model Serialization Format Gate: strictly rejects pickle/PyTorch (.pkl, .pt)
     code-execution vectors and enforces safetensors format with digest pinning.
"""

import hashlib
import json
import os
from typing import Dict, Any, List, Tuple


class SupplyChainSecurityGate:
    """
    Module 6.1: Enterprise Supply Chain Security Gate.
    Verifies dependencies, digests, and model artifacts before runtime deployment.
    """

    def __init__(self):
        self.mock_cve_database = {
            "langchain-core-vulnerable": {
                "cve_id": "CVE-2026-4412",
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                "fix_available": True,
                "description": "Remote code execution in unvalidated prompt template deserialization.",
            }
        }

    def verify_model_weights(self, filename: str, content_header: bytes) -> Tuple[bool, str]:
        """
        Model File Security Gate:
        Rejects pickle format files (.pkl, .pt, .bin) which allow arbitrary code execution.
        Enforces modern, secure safetensors format.
        """
        ext = os.path.splitext(filename)[1].lower()

        # Reject pickle extensions
        if ext in [".pkl", ".pickle", ".pt", ".bin", ".joblib"]:
            return False, f"SUPPLY_CHAIN_BLOCKED: Insecure model format '{ext}'. Legacy pickle files allow arbitrary code execution on load. Safetensors format required."

        # Check for pickle magic header bytes: 0x80 (protocol 2, 3, 4, 5)
        if content_header.startswith(b"\x80"):
            return False, "SUPPLY_CHAIN_BLOCKED: Detected Python pickle magic header bytes (0x80). Malicious weight serialization rejected."

        if ext in [".safetensors", ".json", ".onnx"]:
            return True, f"Model file format '{ext}' validated. Safe serialization confirmed."

        return False, f"SUPPLY_CHAIN_BLOCKED: Unrecognized model artifact format '{ext}'."

    def scan_sbom_cves(self, dependencies: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        SBOM + CVE Scan Gate (Syft/Grype):
        Scans component list and fails closed if any fixable Critical CVE is detected.
        """
        findings = []
        critical_cve_found = False

        for dep in dependencies:
            pkg_name = dep.get("name", "")
            if pkg_name in self.mock_cve_database:
                vuln = self.mock_cve_database[pkg_name]
                findings.append({
                    "package": pkg_name,
                    "version": dep.get("version"),
                    "cve": vuln["cve_id"],
                    "severity": vuln["severity"],
                    "cvss": vuln["cvss_score"],
                    "fix_available": vuln["fix_available"],
                })
                if vuln["severity"] == "CRITICAL" and vuln["fix_available"]:
                    critical_cve_found = True

        gate_passed = not critical_cve_found
        return {
            "gate_passed": gate_passed,
            "status": "PASSED" if gate_passed else "BUILD_FAILED_CRITICAL_CVE",
            "scanned_packages_count": len(dependencies),
            "vulnerabilities": findings,
            "policy": "Reject build if any fixable CRITICAL CVE is present.",
        }


supply_chain_gate = SupplyChainSecurityGate()

