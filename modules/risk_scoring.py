
class AegisRiskScorer:

    def calculate_risk(self, event, detection):

        score = 0
        reasons = []

        # Failed login attempts
        failed = event.get("failed_logins", 0)

        if failed >= 8:
            score += 25
            reasons.append("Critical number of failed login attempts")
        elif failed >= 5:
            score += 18
            reasons.append("High number of failed login attempts")
        elif failed >= 3:
            score += 10
            reasons.append("Multiple failed login attempts")

        # IP reputation
        reputation = event.get("ip_reputation", 100)

        if reputation < 15:
            score += 25
            reasons.append("Very poor IP reputation")
        elif reputation < 30:
            score += 15
            reasons.append("Low IP reputation")

        # Unusual location
        if event.get("unusual_location", 0) == 1:
            score += 15
            reasons.append("Access from an unusual location")

        # Device risk
        device_risk = event.get("device_risk", 0)

        if device_risk >= 85:
            score += 20
            reasons.append("High-risk device detected")
        elif device_risk >= 70:
            score += 10
            reasons.append("Elevated device risk")

        # Data transfer
        transfer = event.get("data_transfer_mb", 0)

        if transfer > 1000:
            score += 20
            reasons.append("Extremely high data transfer")
        elif transfer > 500:
            score += 12
            reasons.append("Unusually high data transfer")

        # Access denied
        denied = event.get("access_denied", 0)

        if denied >= 5:
            score += 15
            reasons.append("Repeated access denied events")

        # Night access
        if event.get("night_access", 0) == 1:
            score += 5
            reasons.append("Unusual login time")

        # ML detection evidence
        if detection.get("is_anomaly", False):
            score += 10
            reasons.append("Isolation Forest detected an anomaly")

        if detection.get("rf_prediction", 0) == 1:
            reasons.append("Random Forest classified event as suspicious")

        # Cap risk score
        score = min(score, 100)

        # Determine severity
        if score >= 80:
            severity = "Critical"
        elif score >= 60:
            severity = "High"
        elif score >= 35:
            severity = "Medium"
        elif score > 0:
            severity = "Low"
        else:
            severity = "Minimal"

        if not reasons:
            reasons.append("No major suspicious indicators found")

        return {
            "risk_score": score,
            "severity": severity,
            "reasons": reasons
        }


if __name__ == "__main__":

    scorer = AegisRiskScorer()

    sample_event = {
        "failed_logins": 8,
        "ip_reputation": 8,
        "unusual_location": 1,
        "device_risk": 95,
        "data_transfer_mb": 850,
        "access_denied": 7,
        "night_access": 1
    }

    sample_detection = {
        "is_anomaly": True,
        "rf_prediction": 1
    }

    result = scorer.calculate_risk(
        sample_event,
        sample_detection
    )

    print("=" * 50)
    print("       AEGIS-AI RISK ASSESSMENT")
    print("=" * 50)

    print("Risk Score:", result["risk_score"], "/ 100")
    print("Severity:", result["severity"])

    print("\nThreat Reasons:")

    for reason in result["reasons"]:
        print("-", reason)

    print("\nTASK 6 COMPLETED SUCCESSFULLY!")

