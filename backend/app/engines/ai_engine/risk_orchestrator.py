"""
CyberShield AI
Central Risk Orchestrator

Responsibilities:
- Normalize scanner risk levels
- Compare scanner risks
- Calculate master risk
- Build risk breakdown
- Preserve Unknown for unavailable assessments
"""

from typing import Any


RISK_ORDER = {
    "Unknown": 0,
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}


VALID_RISKS = set(RISK_ORDER.keys())


def normalize_risk(risk: Any) -> str:
    """
    Normalize a risk value.

    None, empty, invalid, or unavailable values become Unknown.
    Unknown must not be converted to Low.
    """

    if risk is None:
        return "Unknown"

    normalized = str(risk).strip().lower()

    if not normalized:
        return "Unknown"

    risk_mapping = {
        "unknown": "Unknown",
        "not assessed": "Unknown",
        "not_assessed": "Unknown",
        "unavailable": "Unknown",
        "failed": "Unknown",
        "error": "Unknown",
        "low": "Low",
        "medium": "Medium",
        "moderate": "Medium",
        "high": "High",
        "critical": "Critical",
    }

    return risk_mapping.get(
        normalized,
        "Unknown",
    )


def get_highest_risk(
    *risks: str | None,
) -> str:
    """
    Return the highest assessed risk.

    Unknown values are ignored when at least one valid
    assessed risk exists. If no valid assessment exists,
    return Unknown.
    """

    highest = "Unknown"

    for risk in risks:
        normalized = normalize_risk(risk)

        if normalized == "Unknown":
            continue

        if (
            RISK_ORDER[normalized]
            > RISK_ORDER[highest]
        ):
            highest = normalized

    return highest


def _get_vulnerability_risk(
    vulnerability_result: dict | None,
) -> str:
    """
    Extract the vulnerability scanner risk safely.
    """

    if not isinstance(vulnerability_result, dict):
        return "Unknown"

    risk = vulnerability_result.get("overall_risk")

    if risk is None:
        risk = vulnerability_result.get("risk_level")

    return normalize_risk(risk)


def calculate_master_risk(
    web_result: dict | None = None,
    network_result: dict | None = None,
    phishing_result: dict | None = None,
    vulnerability_result: dict | None = None,
) -> str:
    """
    Calculate overall risk using the highest assessed risk.

    Failed or missing components do not become Low risk.
    """

    risks: list[str] = []

    if isinstance(web_result, dict):
        risks.append(
            normalize_risk(
                web_result.get("risk_level")
            )
        )

    if isinstance(network_result, dict):
        risks.append(
            normalize_risk(
                network_result.get("risk_level")
            )
        )

    if isinstance(vulnerability_result, dict):
        risks.append(
            _get_vulnerability_risk(
                vulnerability_result
            )
        )

    if isinstance(phishing_result, dict):
        risks.append(
            normalize_risk(
                phishing_result.get("risk_level")
            )
        )

    return get_highest_risk(*risks)


def _get_component_risk(
    result: dict | None,
    risk_key: str = "risk_level",
) -> str:
    """
    Safely extract an individual component risk.
    """

    if not isinstance(result, dict):
        return "Unknown"

    return normalize_risk(
        result.get(risk_key)
    )


def build_risk_summary(
    web_result: dict | None = None,
    network_result: dict | None = None,
    phishing_result: dict | None = None,
    vulnerability_result: dict | None = None,
) -> dict:
    """
    Build a structured risk summary for Master Scan.
    """

    overall_risk = calculate_master_risk(
        web_result=web_result,
        network_result=network_result,
        phishing_result=phishing_result,
        vulnerability_result=vulnerability_result,
    )

    web_risk = _get_component_risk(
        web_result
    )

    network_risk = _get_component_risk(
        network_result
    )

    vulnerability_risk = _get_vulnerability_risk(
        vulnerability_result
    )

    phishing_risk = _get_component_risk(
        phishing_result
    )

    phishing_confidence = None

    if isinstance(phishing_result, dict):
        confidence = phishing_result.get(
            "confidence"
        )

        if isinstance(confidence, (int, float)):
            phishing_confidence = round(
                max(
                    0.0,
                    min(
                        float(confidence),
                        1.0,
                    ),
                ),
                4,
            )

    risk_score = RISK_ORDER[overall_risk]

    return {
        "overall_risk": overall_risk,
        "risk_score": risk_score,
        "risk_breakdown": {
            "web": web_risk,
            "network": network_risk,
            "vulnerability": vulnerability_risk,
            "phishing": phishing_risk,
        },
        "phishing_confidence": phishing_confidence,
    }


def orchestrate_risk(
    results: dict,
) -> dict:
    """
    Central risk orchestration for Master Scan.
    """

    if not isinstance(results, dict):
        return build_risk_summary()

    return build_risk_summary(
        web_result=results.get("web_scan"),
        network_result=results.get("network_scan"),
        vulnerability_result=results.get("vulnerability"),
        phishing_result=results.get("phishing"),
    
)
