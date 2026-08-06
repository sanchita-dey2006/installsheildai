"""
InstallShield AI - Recommendation Engine
Generates actionable, risk-tailored recommendations for installers.
"""

import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class RecommendationEngine:
    """Generates context-aware security recommendations."""

    @staticmethod
    def generate_recommendations(
        risk_score: int,
        risk_tier: str,
        threat_category: str,
        sig_info: Dict[str, Any],
        is_trusted_publisher: bool,
        entropy: float,
        flags: List[str]
    ) -> List[Dict[str, str]]:
        """
        Generate prioritized recommendations based on security risk assessment.

        :return: List of recommendation dicts with 'action', 'level', and 'description'.
        """
        recommendations: List[Dict[str, str]] = []
        sig_status = str(sig_info.get("status", "Unknown"))
        publisher = str(sig_info.get("publisher", "Unknown"))

        # High Risk / Malicious (Score 61-100)
        if risk_score >= 61:
            recommendations.append({
                "action": "Do Not Execute",
                "level": "CRITICAL",
                "description": "Do not run or execute this installer. High probability of malicious intent or payload delivery."
            })
            recommendations.append({
                "action": "Delete Immediately",
                "level": "HIGH",
                "description": "Purge the file from your local storage to prevent accidental execution."
            })
            recommendations.append({
                "action": "Upload to VirusTotal",
                "level": "MEDIUM",
                "description": "Upload the file hash or binary to VirusTotal to verify multi-engine antivirus detection."
            })
            recommendations.append({
                "action": "Request IT Administrator Review",
                "level": "MEDIUM",
                "description": "Notify your organization's IT Security team or Security Operations Center (SOC)."
            })

        # Suspicious (Score 41-60)
        elif risk_score >= 41:
            recommendations.append({
                "action": "Run Inside Sandbox",
                "level": "HIGH",
                "description": "If execution is required, isolate the file inside a sandbox environment (e.g. Windows Sandbox, Cuckoo)."
            })
            recommendations.append({
                "action": "Scan with Windows Defender",
                "level": "MEDIUM",
                "description": "Run a full file scan using Windows Defender or an endpoint detection and response (EDR) agent."
            })
            recommendations.append({
                "action": "Download from Official Website",
                "level": "MEDIUM",
                "description": "Re-download the installer directly from the official software vendor's web domain."
            })
            if sig_status != "Valid" or not is_trusted_publisher:
                recommendations.append({
                    "action": "Verify Publisher",
                    "level": "MEDIUM",
                    "description": f"Publisher '{publisher}' is unverified or untrusted. Verify digital signature certificates."
                })

        # Low Risk (Score 21-40)
        elif risk_score >= 21:
            if not is_trusted_publisher:
                recommendations.append({
                    "action": "Verify Publisher",
                    "level": "MEDIUM",
                    "description": f"Verify publisher credentials for '{publisher}' before running the installer."
                })
                recommendations.append({
                    "action": "Download from Official Website",
                    "level": "LOW",
                    "description": "Ensure the installer file was retrieved from the vendor's official verified portal."
                })
            else:
                recommendations.append({
                    "action": "Scan with Windows Defender",
                    "level": "LOW",
                    "description": "Perform standard local antivirus check prior to installation."
                })

        # Trusted / Clean (Score 0-20)
        else:
            recommendations.append({
                "action": "Safe to Install",
                "level": "INFO",
                "description": "The file is signed by a recognized trusted publisher and exhibits clean static analysis characteristics."
            })

        # Supplementary recommendations based on specific findings
        if entropy > 7.5 and not any(r["action"] == "Run Inside Sandbox" for r in recommendations):
            recommendations.append({
                "action": "Run Inside Sandbox",
                "level": "HIGH",
                "description": "Binary exhibits extreme Shannon entropy (packed/encrypted). Test execution safely in a sandbox."
            })

        return recommendations
