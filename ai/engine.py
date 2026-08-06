"""
InstallShield AI - Unified AI Engine Facade
Central coordinator linking scoring, classification, recommendations, explanation, and PDF reporting.
"""

import logging
from typing import Dict, Any, List, Optional

from ai.scoring import RiskScoringEngine
from ai.classification import ThreatClassifier
from ai.recommendation import RecommendationEngine
from ai.explanation import ExplainableAIGenerator
from ai.pdf_generator import PDFReportGenerator

logger = logging.getLogger(__name__)


class AIEngine:
    """Unified AI Engine facade for software installer security assessment."""

    @staticmethod
    def analyze(
        sig_info: Dict[str, Any],
        is_trusted_publisher: bool,
        entropy: float,
        entropy_stats: Dict[str, Any],
        string_analysis: Dict[str, Any],
        file_metadata: Dict[str, Any],
        hashes: Optional[Dict[str, Any]] = None,
        filename: str = "Unknown",
        filepath: str = "Unknown",
        scan_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Run complete AI security analysis pipeline across all sub-engines.

        :return: Structured comprehensive AI Assessment dictionary.
        """
        if hashes is None:
            hashes = {}

        # 1. Risk Scoring Engine
        scoring_res = RiskScoringEngine.calculate_score(
            sig_info=sig_info,
            is_trusted_publisher=is_trusted_publisher,
            entropy=entropy,
            entropy_stats=entropy_stats,
            string_analysis=string_analysis,
            file_metadata=file_metadata
        )

        risk_score = scoring_res["risk_score"]
        risk_tier = scoring_res["risk_tier"]
        score_breakdown = scoring_res["score_breakdown"]
        flags = scoring_res["flags"]

        # 2. Threat Classification Engine
        classification_res = ThreatClassifier.classify(
            risk_score=risk_score,
            sig_info=sig_info,
            is_trusted_publisher=is_trusted_publisher,
            entropy=entropy,
            entropy_stats=entropy_stats,
            string_analysis=string_analysis
        )
        threat_category = classification_res["category"]

        # 3. Recommendation Engine
        recommendations = RecommendationEngine.generate_recommendations(
            risk_score=risk_score,
            risk_tier=risk_tier,
            threat_category=threat_category,
            sig_info=sig_info,
            is_trusted_publisher=is_trusted_publisher,
            entropy=entropy,
            flags=flags
        )

        # 4. Explainable AI Generator
        explanation = ExplainableAIGenerator.generate_explanation(
            risk_score=risk_score,
            risk_tier=risk_tier,
            threat_category=threat_category,
            sig_info=sig_info,
            is_trusted_publisher=is_trusted_publisher,
            entropy=entropy,
            string_analysis=string_analysis,
            score_breakdown=score_breakdown,
            flags=flags
        )

        # Consolidated Payload
        assessment = {
            "scan_id": scan_id,
            "filename": filename,
            "filepath": filepath,
            "risk_score": risk_score,
            "risk_tier": risk_tier,
            "threat_level": risk_tier,  # Backwards compatibility
            "threat_category": threat_category,
            "score_breakdown": score_breakdown,
            "flags": flags,
            "recommendations": recommendations,
            "explanation": explanation,
            "signature_status": sig_info.get("status", "Unknown"),
            "publisher": sig_info.get("publisher", "Unknown"),
            "is_trusted": is_trusted_publisher,
            "entropy": round(entropy, 2),
            "entropy_verdict": entropy_stats.get("verdict", "Normal"),
            "hashes": hashes,
            "metadata": file_metadata,
            "suspicious_apis": string_analysis.get("suspicious_apis", []),
            "suspicious_keywords": string_analysis.get("suspicious_keywords", []),
            "urls": string_analysis.get("urls", [])
        }

        return assessment

    @staticmethod
    def generate_pdf_report(analysis_data: Dict[str, Any], output_path: str) -> str:
        """
        Generate a PDF security assessment report.

        :param analysis_data: Complete AI Assessment dictionary from analyze().
        :param output_path: Desired output PDF path.
        :return: Path to generated PDF report.
        """
        return PDFReportGenerator.generate_report(analysis_data, output_path)
