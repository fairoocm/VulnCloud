"""Simple, transparent scoring for VulnCloud assessment results."""


def calculate_security_score(headers, tls=None):
    """Score applicable header checks and HTTPS certificate verification."""
    checks = []
    for item in headers or []:
        status = str(item.get("status", "")).upper()
        if status == "PRESENT":
            checks.append(True)
        elif status == "MISSING":
            checks.append(False)
        # NOT APPLICABLE checks are intentionally excluded.

    if tls is not None:
        checks.append(bool(tls.get("success")) and
                      str(tls.get("verification", "")).upper() == "VALID")

    if not checks:
        return {"score": 0, "rating": "Not Rated", "passed": 0,
                "total": 0, "message": "No applicable security checks were available."}

    passed = sum(checks)
    total = len(checks)
    score = round((passed / total) * 100)
    if score >= 90:
        rating = "Excellent"
    elif score >= 75:
        rating = "Good"
    elif score >= 50:
        rating = "Moderate"
    else:
        rating = "Poor"
    return {"score": score, "rating": rating, "passed": passed,
            "total": total, "message": f"{passed} of {total} applicable checks passed."}
