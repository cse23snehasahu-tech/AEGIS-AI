
from flask import Flask, request, jsonify
from pathlib import Path
import sys
import traceback

# Add project root to Python path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from modules.threat_detection import AegisThreatDetector
from modules.risk_scoring import AegisRiskScorer
from modules.intelligent_response import AegisIntelligentResponse

from database.db_manager import (
    initialize_db,
    save_event,
    get_events,
    get_stats
)

app = Flask(__name__)

# Initialize database and AI modules
initialize_db()

detector = AegisThreatDetector()
risk_scorer = AegisRiskScorer()
response_engine = AegisIntelligentResponse()

REQUIRED_FEATURES = [
    "login_attempts",
    "failed_logins",
    "access_hour",
    "data_transfer_mb",
    "ip_reputation",
    "privilege_level",
    "unusual_location",
    "access_denied",
    "session_duration",
    "device_risk"
]


def prepare_event(event):
    """Validate input and create engineered features."""

    if not isinstance(event, dict):
        raise ValueError("Request must contain a JSON object.")

    missing = [
        feature for feature in REQUIRED_FEATURES
        if feature not in event
    ]

    if missing:
        raise ValueError(
            "Missing required features: " + ", ".join(missing)
        )

    prepared = event.copy()

    login_attempts = max(float(prepared["login_attempts"]), 1)

    prepared["night_access"] = int(
        float(prepared["access_hour"]) < 6
        or float(prepared["access_hour"]) >= 22
    )

    prepared["failed_login_ratio"] = (
        float(prepared["failed_logins"]) / login_attempts
    )

    prepared["high_data_transfer"] = int(
        float(prepared["data_transfer_mb"]) > 500
    )

    prepared["high_device_risk"] = int(
        float(prepared["device_risk"]) > 75
    )

    return prepared


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "project": "AEGIS-AI",
        "message": "AI-Powered Cloud Security Threat Detection API",
        "status": "running"
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "database": "initialized",
        "system": "AEGIS-AI"
    })


@app.route("/analyze", methods=["POST"])
def analyze_event():
    try:
        data = request.get_json(silent=True)

        if data is None:
            return jsonify({
                "success": False,
                "error": "Please send valid JSON."
            }), 400

        event = prepare_event(data)

        # Detect suspicious activity
        detection = detector.detect_threat(event)

        # Calculate risk score
        risk = risk_scorer.calculate_risk(event, detection)

        # Generate response recommendations
        response = response_engine.generate_response(
            event, detection, risk
        )

        # Save result in SQLite database
        record_id = save_event(
            event, detection, risk, response
        )

        return jsonify({
            "success": True,
            "record_id": record_id,
            "event": event,
            "detection": detection,
            "risk": risk,
            "response": response
        }), 200

    except ValueError as error:
        return jsonify({
            "success": False,
            "error": str(error)
        }), 400

    except Exception as error:
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


@app.route("/events", methods=["GET"])
def event_history():
    try:
        limit = request.args.get("limit", default=100, type=int)
        limit = max(1, min(limit, 500))

        return jsonify({
            "success": True,
            "events": get_events(limit)
        })

    except Exception as error:
        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


@app.route("/stats", methods=["GET"])
def statistics():
    try:
        return jsonify({
            "success": True,
            "statistics": get_stats()
        })

    except Exception as error:
        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


if __name__ == "__main__":
    print("=" * 50)
    print("       AEGIS-AI SECURITY API")
    print("=" * 50)
    print("API:      http://127.0.0.1:5000")
    print("Health:   http://127.0.0.1:5000/health")
    print("Events:   http://127.0.0.1:5000/events")
    print("Stats:    http://127.0.0.1:5000/stats")
    print("=" * 50)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
