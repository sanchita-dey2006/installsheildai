"""
InstallShield AI - Explainable AI Generator
Generates clear, contextual, human-readable explanations for security assessments.
"""

import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class ExplainableAIGenerator:
    """Generates detailed, contextual human-readable security explanations."""

    @staticmethod
    def generate_explanation(
        risk_score: int,
        risk_tier: str,
        threat_category: str,
        sig_info: Dict[str, Any],
        is_trusted_publisher: bool,
        entropy: float,
        string_analysis: Dict[str, Any],
        score_breakdown: List[Dict[str, Any]],
        flags: List[str]
    ) -> Dict[str, Any]:
        """
        Generate contextual explanation narrative, positive indicators, and risk factor breakdown.

        :return: Dict containing 'summary_narrative', 'positive_indicators', and 'risk_factors'.
        """
        publisher = str(sig_info.get("publisher", "Unknown"))
        sig_status = str(sig_info.get("status", "Unknown"))
        apis = string_analysis.get("suspicious_apis", [])
        keywords = string_analysis.get("suspicious_keywords", [])
        urls = string_analysis.get("urls", [])

        positive_indicators: List[str] = []
        risk_factors: List[str] = []

        # Evaluate positive indicators
        if sig_status == "Valid":
            positive_indicators.append(f"Authenticode signature is valid and cryptographically intact.")
            if is_trusted_publisher:
                positive_indicators.append(f"Publisher '{publisher}' is recognized in the trusted vendor database.")
        if entropy <= 6.5:
            positive_indicators.append(f"Binary Shannon entropy ({entropy:.2f}/8.0) is within normal uncompressed executable bounds.")
        if not apis:
            positive_indicators.append("No suspicious native injection or execution APIs detected in binary strings.")
        if not keywords:
            positive_indicators.append("No dangerous command utility keywords detected.")

        # Build detailed summary narrative
        narrative_parts: List[str] = []

        narrative_parts.append(
            f"InstallShield AI completed static security evaluation for this installer. "
            f"The overall calculated risk score is {risk_score}/100, placing the file in the '{risk_tier}' risk tier "
            f"and classifying it as '{threat_category}'."
        )

        if sig_status == "Valid" and is_trusted_publisher:
            narrative_parts.append(
                f"The executable is digitally signed by a verified trusted publisher ({publisher}). "
                f"This strongly reduces the likelihood of unauthorized software modification or malicious spoofing."
            )
        elif sig_status == "Valid" and not is_trusted_publisher:
            narrative_parts.append(
                f"The executable is digitally signed by '{publisher}', but this publisher is not listed in the "
                f"trusted publisher database. Caution is recommended."
            )
        else:
            narrative_parts.append(
                f"The executable is unsigned or possesses an unverified digital signature ({sig_status}). "
                f"Unsigned installers carry an inherently elevated risk because file integrity cannot be guaranteed."
            )

        if entropy > 7.5:
            narrative_parts.append(
                f"The file exhibits extremely high Shannon entropy ({entropy:.2f}/8.0), indicating that binary code "
                f"sections are heavily packed, compressed, or encrypted. Packers are frequently used to obfuscate software payloads."
            )
        elif entropy > 6.8:
            narrative_parts.append(
                f"Elevated Shannon entropy ({entropy:.2f}/8.0) was detected, suggesting compressed code sections or custom packing."
            )

        if apis or keywords or urls:
            indicators_summary = []
            if apis:
                indicators_summary.append(f"{len(apis)} suspicious native APIs (e.g. {', '.join(apis[:3])})")
            if keywords:
                indicators_summary.append(f"{len(keywords)} command utilities/keywords (e.g. {', '.join(keywords[:3])})")
            if urls:
                indicators_summary.append(f"{len(urls)} embedded network URLs/IP addresses")

            narrative_parts.append(
                f"Static string extraction uncovered key indicators: {', '.join(indicators_summary)}. "
                f"These characteristics significantly increase the probability of suspicious runtime behavior."
            )

        summary_narrative = " ".join(narrative_parts)

        # Build risk factors list
        for item in score_breakdown:
            if item.get("weight", 0) > 0:
                risk_factors.append(f"[{item['factor']} (+{item['weight']} pts)] {item['reason']}")

        return {
            "summary_narrative": summary_narrative,
            "positive_indicators": positive_indicators,
            "risk_factors": risk_factors
        }
