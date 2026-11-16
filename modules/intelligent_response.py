
class AegisIntelligentResponse:

    def generate_response(self, event, detection, risk):

        recommendations = []
        actions = []

        # Failed login detection
        if event.get("failed_logins", 0) >= 5:
            recommendations.append(
                "Investigate repeated failed login attempts."
            )
            actions.append(
                "Recommend temporary account protection and MFA verification."
            )

        # IP reputation
        if event.get("ip_reputation", 100) < 30:
            recommendations.append(
                "Investigate the suspicious IP address."
            )
            actions.append(
                "Recommend restricting IP access after verification."
            )

        # Unusual location
        if event.get("unusual_location", 0) == 1:
            recommendations.append(
                "Verify the user's geographical access location."
            )
            actions.append(
                "Recommend additional identity verification."
            )

        # Device risk
        if event.get("device_risk", 0) >= 75:
            recommendations.append(
                "Perform a security scan on the risky device."
            )
            actions.append(
                "Recommend device isolation for security investigation."
            )

        # Data transfer
        if event.get("data_transfer_mb", 0) > 500:
            recommendations.append(
                "Investigate unusually large data transfers."
            )
            actions.append(
                "Recommend temporary data transfer restrictions."
            )

        # Access denied
        if event.get("access_denied", 0) >= 5:
            recommendations.append(
                "Review access permissions and denied requests."
            )

        # Privilege level
        if event.get("privilege_level", 0) >= 3:
            recommendations.append(
                "Audit privileged account activities."
            )

        # ML anomaly
        if detection.get("is_anomaly", False):
            recommendations.append(
                "Investigate anomalous system behaviour."
            )

        # Severity-based recommendations
        severity = risk.get("severity", "Minimal")

        if severity == "Critical":
            actions.append(
                "URGENT: Escalate incident to the security response team."
            )

        elif severity == "High":
            actions.append(
                "Escalate this security event for immediate review."
            )

        elif severity == "Medium":
            actions.append(
                "Monitor the event and investigate suspicious patterns."
            )

        if not recommendations:
            recommendations.append(
                "No immediate security intervention required."
            )

        if not actions:
            actions.append(
                "Continue routine security monitoring."
            )

        return {
            "severity": severity,
            "recommendations": recommendations,
            "suggested_actions": actions,
            "execution_mode": "RECOMMENDATION ONLY",
            "automatic_execution": False
        }


if __name__ == "__main__":

    response_engine = AegisIntelligentResponse()

    sample_event = {
        "failed_logins": 8,
        "ip_reputation": 8,
        "unusual_location": 1,
        "device_risk": 95,
        "data_transfer_mb": 850,
        "access_denied": 7,
        "privilege_level": 3
    }

    sample_detection = {
        "is_anomaly": True
    }

    sample_risk = {
        "risk_score": 95,
        "severity": "Critical"
    }

    result = response_engine.generate_response(
        sample_event,
        sample_detection,
        sample_risk
    )

    print("=" * 60)
    print("       AEGIS-AI INTELLIGENT RESPONSE SYSTEM")
    print("=" * 60)

    print("\nSeverity:", result["severity"])

    print("\nRecommendations:")
    for item in result["recommendations"]:
        print("-", item)

    print("\nSuggested Actions:")
    for item in result["suggested_actions"]:
        print("-", item)

    print("\nExecution Mode:", result["execution_mode"])
    print("Automatic Execution:", result["automatic_execution"])

    print("\nTASK 7 COMPLETED SUCCESSFULLY!")
