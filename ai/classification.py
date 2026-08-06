"""
InstallShield AI - Threat Classification Engine
Deterministically classifies software installers into granular threat categories.
"""

import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

THREAT_CATEGORIES = [
    "Trusted Software",
    "Unknown Software",
    "Potentially Unsafe",
    "Trojan",
    "Spyware",
    "Ransomware",
    "Backdoor",
    "Adware",
    "Packed Executable",
    "Suspicious Installer",
    "Unknown Threat",
]


class ThreatClassifier:
    """Deterministic threat category classification engine."""

    @staticmethod
    def classify(
        risk_score: int,
        sig_info: Dict[str, Any],
        is_trusted_publisher: bool,
        entropy: float,
        entropy_stats: Dict[str, Any],
        string_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Classify installer into an explicit threat category with contextual reasoning.

        :return: Dict containing category name, confidence score, and classification breakdown.
        """
        sig_status = str(sig_info.get("status", "Unknown"))
        publisher = str(sig_info.get("publisher", "Unknown"))
        apis = [a.lower() for a in string_analysis.get("suspicious_apis", [])]
        keywords = [k.lower() for k in string_analysis.get("suspicious_keywords", [])]
        urls = string_analysis.get("urls", [])
        entropy_verdict = str(entropy_stats.get("verdict", ""))

        category = "Unknown Threat"
        confidence = "Medium"
        reasons: List[str] = []

        # Category 1: Trusted Software
        if sig_status == "Valid" and is_trusted_publisher and risk_score <= 25:
            category = "Trusted Software"
            confidence = "High"
            reasons.append(f"Valid digital signature from verified publisher '{publisher}'")
            reasons.append(f"Low overall risk score ({risk_score}/100)")
            return {
                "category": category,
                "confidence": confidence,
                "reasons": reasons
            }

        # Category 2: Ransomware indicators
        ransomware_apis = {"virtualprotectex", "writeprocessmemory", "adjusttokenprivileges"}
        ransomware_kws = {"vssadmin", "shadow", "encrypt", "crypto", "bypass"}
        has_ransom_apis = any(a in apis for a in ransomware_apis)
        has_ransom_kws = any(k in keywords for k in ransomware_kws)

        if entropy > 7.6 and (has_ransom_apis or has_ransom_kws):
            category = "Ransomware"
            confidence = "High"
            reasons.append(f"High entropy binary ({entropy:.2f}) with potential file manipulation patterns")
            if has_ransom_apis:
                reasons.append("Detected memory protection and process modification APIs")
            if has_ransom_kws:
                reasons.append("Detected persistence or security bypass keywords")
            return {
                "category": category,
                "confidence": confidence,
                "reasons": reasons
            }

        # Category 3: Backdoor / Reverse Shell
        backdoor_apis = {"createremotethread", "rtlcreateuserthread", "ntunmapviewofsection"}
        backdoor_kws = {"powershell", "powershell.exe", "downloadstring", "invoke-expression", "iex", "cmd.exe"}
        has_backdoor_apis = any(a in apis for a in backdoor_apis)
        has_backdoor_kws = any(k in keywords for k in backdoor_kws)

        if has_backdoor_apis or (has_backdoor_kws and len(urls) > 0 and risk_score >= 50):
            category = "Backdoor"
            confidence = "High" if has_backdoor_apis else "Medium"
            if has_backdoor_apis:
                reasons.append("Detected remote thread execution / code injection APIs")
            if has_backdoor_kws:
                reasons.append("Detected command utility / script execution triggers")
            if urls:
                reasons.append(f"Contains remote C2 server network links ({len(urls)} URLs)")
            return {
                "category": category,
                "confidence": confidence,
                "reasons": reasons
            }

        # Category 4: Spyware / Keylogger
        spyware_apis = {"setwindowshookexa", "setwindowshookexw", "isdebuggerpresent", "readprocessmemory"}
        spyware_kws = {"keylogger", "mimikatz", "bypass"}
        has_spyware = any(a in apis for a in spyware_apis) or any(k in keywords for k in spyware_kws)

        if has_spyware:
            category = "Spyware"
            confidence = "Medium"
            reasons.append("Detected Windows event hooking or process memory inspection APIs")
            return {
                "category": category,
                "confidence": confidence,
                "reasons": reasons
            }

        # Category 5: Trojan
        trojan_apis = {"virtualalloc", "virtualallocex", "writeprocessmemory", "urldownloadtofilea", "urldownloadtofilew", "winexec"}
        has_trojan_apis = sum(1 for a in apis if a in trojan_apis) >= 2

        if (has_trojan_apis or (len(urls) > 0 and "urldownloadtofile" in "".join(apis))) and risk_score >= 50:
            category = "Trojan"
            confidence = "High"
            reasons.append("Binary exhibits Trojan traits: native code execution combined with download capabilities")
            reasons.append(f"Elevated risk score ({risk_score}/100)")
            return {
                "category": category,
                "confidence": confidence,
                "reasons": reasons
            }

        # Category 6: Packed Executable
        if entropy > 7.3 or "Packed" in entropy_verdict or "Encrypted" in entropy_verdict:
            category = "Packed Executable"
            confidence = "High"
            reasons.append(f"Binary Shannon entropy ({entropy:.2f}/8.0) indicates packed or obfuscated code")
            if sig_status != "Valid":
                reasons.append("Executable is unpacked or lacks valid publisher verification")
            return {
                "category": category,
                "confidence": confidence,
                "reasons": reasons
            }

        # Category 7: Adware
        if len(urls) >= 3 and risk_score < 60 and not has_trojan_apis:
            category = "Adware"
            confidence = "Medium"
            reasons.append(f"Contains multiple embedded URLs ({len(urls)} links) with low to moderate binary risk")
            return {
                "category": category,
                "confidence": confidence,
                "reasons": reasons
            }

        # Category 8: Suspicious Installer
        if risk_score >= 60:
            category = "Suspicious Installer"
            confidence = "High"
            reasons.append(f"High risk score ({risk_score}/100) triggered by multiple risk indicators")
            if sig_status != "Valid":
                reasons.append("Unsigned or untrusted digital signature")
            return {
                "category": category,
                "confidence": confidence,
                "reasons": reasons
            }

        # Category 9: Potentially Unsafe
        if risk_score >= 35 or sig_status == "Valid" and not is_trusted_publisher:
            category = "Potentially Unsafe"
            confidence = "Medium"
            reasons.append(f"Moderate risk score ({risk_score}/100)")
            if not is_trusted_publisher and publisher != "Unknown":
                reasons.append(f"Publisher '{publisher}' is unverified")
            return {
                "category": category,
                "confidence": confidence,
                "reasons": reasons
            }

        # Category 10: Unknown Software
        if sig_status != "Valid" or not is_trusted_publisher:
            category = "Unknown Software"
            confidence = "Low"
            reasons.append("Installer comes from an unverified or unknown publisher")
            reasons.append(f"Low risk score ({risk_score}/100)")
            return {
                "category": category,
                "confidence": confidence,
                "reasons": reasons
            }

        # Default fallback
        category = "Trusted Software" if risk_score <= 20 else "Unknown Software"
        confidence = "Low"
        reasons.append(f"Risk evaluation score: {risk_score}/100")
        return {
            "category": category,
            "confidence": confidence,
            "reasons": reasons
        }
