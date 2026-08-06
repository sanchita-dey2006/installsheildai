"""
InstallShield AI - Risk Scoring Engine
Calculates explainable, deterministic risk scores (0-100) based on weighted security signals.
"""

import logging
from typing import Dict, Any, List, Tuple

logger = logging.getLogger(__name__)


# High-risk APIs often utilized in code injection, hooking, and privilege escalation
HIGH_RISK_APIS = {
    "VirtualAllocEx", "VirtualProtectEx", "WriteProcessMemory", "ReadProcessMemory",
    "CreateRemoteThread", "RtlCreateUserThread", "NtUnmapViewOfSection",
    "SetWindowsHookExA", "SetWindowsHookExW", "AdjustTokenPrivileges",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent"
}

# General native APIs associated with execution and network activity
GENERAL_SUSPICIOUS_APIS = {
    "VirtualAlloc", "VirtualProtect", "OpenProcess",
    "URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenA", "InternetOpenW",
    "InternetOpenUrlA", "InternetOpenUrlW", "HttpOpenRequestA", "HttpOpenRequestW",
    "WinExec", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
    "CreateProcessA", "CreateProcessW", "RegSetValueExA", "RegSetValueExW",
    "RegCreateKeyExA", "RegCreateKeyExW", "LoadLibraryA", "LoadLibraryW", "GetProcAddress"
}


class RiskScoringEngine:
    """Deterministic, weighted Risk Scoring Engine for software installers."""

    @staticmethod
    def calculate_score(
        sig_info: Dict[str, Any],
        is_trusted_publisher: bool,
        entropy: float,
        entropy_stats: Dict[str, Any],
        string_analysis: Dict[str, Any],
        file_metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Compute weighted risk score (0-100) and risk tier based on security inputs.

        :param sig_info: Dict containing 'status' and 'publisher' from verify_signature.
        :param is_trusted_publisher: Boolean indicating if publisher is in trusted database.
        :param entropy: Shannon entropy float value (0.0 to 8.0).
        :param entropy_stats: Dict containing entropy stats and verdict.
        :param string_analysis: Dict containing suspicious_apis, suspicious_keywords, urls.
        :param file_metadata: Dict containing file metadata (size, file_type, magic_bytes).
        :return: Dict with risk_score, risk_tier, score_breakdown, and flags.
        """
        score = 0
        breakdown: List[Dict[str, Any]] = []
        flags: List[str] = []

        # ------------------------------------------------------------------
        # 1. Digital Signature & Publisher Reputation Evaluation
        # ------------------------------------------------------------------
        sig_status = str(sig_info.get("status", "Unknown"))
        publisher = str(sig_info.get("publisher", "Unknown"))

        if sig_status == "Valid":
            if is_trusted_publisher:
                points = -15
                score += points
                breakdown.append({
                    "factor": "Digital Signature",
                    "weight": points,
                    "reason": f"Valid Authenticode signature from trusted publisher '{publisher}'"
                })
            else:
                points = 15
                score += points
                flags.append(f"Signed by unverified/untrusted publisher: {publisher}")
                breakdown.append({
                    "factor": "Digital Signature",
                    "weight": points,
                    "reason": f"Valid signature, but publisher '{publisher}' is not in trusted database"
                })
        elif sig_status == "NotSigned":
            points = 25
            score += points
            flags.append("Executable is unsigned (no Authenticode digital signature)")
            breakdown.append({
                "factor": "Digital Signature",
                "weight": points,
                "reason": "Binary lacks digital signature, increasing risk of tampering"
            })
        elif sig_status in ("HashMismatch", "NotTrusted", "Error"):
            points = 35
            score += points
            flags.append(f"Digital signature validation failed: {sig_status}")
            breakdown.append({
                "factor": "Digital Signature",
                "weight": points,
                "reason": f"Signature check failed or certificate mismatch ({sig_status})"
            })
        else:
            # Platform not supported or unknown status
            points = 15
            score += points
            breakdown.append({
                "factor": "Digital Signature",
                "weight": points,
                "reason": f"Digital signature status unverified ({sig_status})"
            })

        # ------------------------------------------------------------------
        # 2. Entropy & Compression Analysis
        # ------------------------------------------------------------------
        if entropy > 7.8:
            points = 35
            score += points
            flags.append(f"Extreme Shannon entropy ({entropy:.2f}/8.0): binary is packed/encrypted")
            breakdown.append({
                "factor": "Entropy",
                "weight": points,
                "reason": f"Extreme entropy ({entropy:.2f}/8.0) indicates heavy packer or encryption"
            })
        elif entropy > 7.2:
            points = 25
            score += points
            flags.append(f"High Shannon entropy ({entropy:.2f}/8.0): potential packer or compression")
            breakdown.append({
                "factor": "Entropy",
                "weight": points,
                "reason": f"High entropy ({entropy:.2f}/8.0) suggests compressed/packed sections"
            })
        elif entropy > 6.5:
            points = 10
            score += points
            flags.append(f"Elevated entropy ({entropy:.2f}/8.0)")
            breakdown.append({
                "factor": "Entropy",
                "weight": points,
                "reason": f"Elevated entropy ({entropy:.2f}/8.0)"
            })
        else:
            breakdown.append({
                "factor": "Entropy",
                "weight": 0,
                "reason": f"Normal entropy ({entropy:.2f}/8.0)"
            })

        # ------------------------------------------------------------------
        # 3. Suspicious Native APIs Analysis
        # ------------------------------------------------------------------
        detected_apis = string_analysis.get("suspicious_apis", [])
        if detected_apis:
            high_risk_found = [api for api in detected_apis if api in HIGH_RISK_APIS]
            general_risk_found = [api for api in detected_apis if api in GENERAL_SUSPICIOUS_APIS or api not in HIGH_RISK_APIS]

            api_points = min(len(high_risk_found) * 8 + len(general_risk_found) * 4, 30)
            score += api_points

            if high_risk_found:
                flags.append(f"Detected high-risk code injection APIs: {', '.join(high_risk_found[:4])}")

            breakdown.append({
                "factor": "Suspicious APIs",
                "weight": api_points,
                "reason": f"Detected {len(detected_apis)} suspicious APIs ({', '.join(detected_apis[:5])})"
            })

        # ------------------------------------------------------------------
        # 4. Suspicious Command Utilities & Keywords
        # ------------------------------------------------------------------
        keywords = string_analysis.get("suspicious_keywords", [])
        if keywords:
            kw_points = min(len(keywords) * 6, 25)
            score += kw_points
            flags.append(f"Detected suspicious command utilities/keywords: {', '.join(keywords[:5])}")
            breakdown.append({
                "factor": "Suspicious Keywords",
                "weight": kw_points,
                "reason": f"Found {len(keywords)} suspicious keywords/utilities ({', '.join(keywords[:5])})"
            })

        # ------------------------------------------------------------------
        # 5. Embedded URLs & Network Indicators
        # ------------------------------------------------------------------
        urls = string_analysis.get("urls", [])
        if urls:
            url_points = min(len(urls) * 8, 25)
            score += url_points
            flags.append(f"Embedded network URLs/IP addresses found: {', '.join(urls[:3])}")
            breakdown.append({
                "factor": "Embedded URLs",
                "weight": url_points,
                "reason": f"Found {len(urls)} embedded URLs or remote network addresses"
            })

        # ------------------------------------------------------------------
        # 6. File Metadata & Header Anomaly Check
        # ------------------------------------------------------------------
        file_type = file_metadata.get("file_type", "")
        magic_bytes = file_metadata.get("magic_bytes", "")
        try:
            file_size_num = int(file_metadata.get("file_size", 0))
        except (ValueError, TypeError):
            file_size_num = 0

        if file_size_num > 0 and file_size_num < 10240:  # Suspiciously small installer (< 10 KB)
            points = 10
            score += points
            flags.append("Installer file size is unusually small (< 10 KB)")
            breakdown.append({
                "factor": "File Size Anomaly",
                "weight": points,
                "reason": "File size is unusually small for a standalone installer package"
            })

        # Clamp final score between 0 and 100
        risk_score = max(0, min(100, score))
        risk_tier = RiskScoringEngine.get_risk_tier(risk_score)

        return {
            "risk_score": risk_score,
            "risk_tier": risk_tier,
            "score_breakdown": breakdown,
            "flags": flags
        }

    @staticmethod
    def get_risk_tier(score: int) -> str:
        """
        Classifies risk score into standardized threat risk tiers.

        0–20: Trusted
        21–40: Low Risk
        41–60: Suspicious
        61–80: High Risk
        81–100: Malicious
        """
        if score <= 20:
            return "Trusted"
        elif score <= 40:
            return "Low Risk"
        elif score <= 60:
            return "Suspicious"
        elif score <= 80:
            return "High Risk"
        else:
            return "Malicious"
