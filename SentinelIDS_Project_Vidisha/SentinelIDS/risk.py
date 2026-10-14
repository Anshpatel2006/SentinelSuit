def severity_for_risk(risk_score):
    """Map the normalized 0-100 risk score to the dashboard severity bands."""
    score = max(0, min(100, float(risk_score or 0)))
    if score >= 70:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"
