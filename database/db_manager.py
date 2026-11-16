import sqlite3
import json
from pathlib import Path
from datetime import datetime


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "database" / "aegis_security.db"


def initialize_db():
    """Create the security events table if it does not exist."""

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                severity TEXT,
                risk_score REAL,
                is_threat INTEGER,
                event_data TEXT NOT NULL,
                detection_data TEXT NOT NULL,
                risk_data TEXT NOT NULL,
                response_data TEXT NOT NULL
            )
        """)
        conn.commit()


def _to_json(data):
    """Convert Python and NumPy values into JSON safely."""

    def convert(value):
        if hasattr(value, "item"):
            return value.item()
        return str(value)

    return json.dumps(data, default=convert)


def save_event(event, detection, risk, response):
    """Save one analyzed security event."""

    initialize_db()

    severity = risk.get("severity", "Unknown")
    risk_score = risk.get("risk_score", risk.get("score", 0))
    is_threat = bool(detection.get("is_threat", False))

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute("""
            INSERT INTO security_events (
                created_at, severity, risk_score, is_threat,
                event_data, detection_data, risk_data, response_data
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().isoformat(timespec="seconds"),
            severity,
            float(risk_score),
            int(is_threat),
            _to_json(event),
            _to_json(detection),
            _to_json(risk),
            _to_json(response)
        ))

        conn.commit()
        return cursor.lastrowid


def get_events(limit=100):
    """Return the latest analyzed security events."""

    initialize_db()

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        rows = conn.execute("""
            SELECT * FROM security_events
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

    results = []

    for row in rows:
        item = dict(row)
        item["event_data"] = json.loads(item["event_data"])
        item["detection_data"] = json.loads(item["detection_data"])
        item["risk_data"] = json.loads(item["risk_data"])
        item["response_data"] = json.loads(item["response_data"])
        results.append(item)

    return results


def get_stats():
    """Return basic security monitoring statistics."""

    initialize_db()

    with sqlite3.connect(DB_PATH) as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM security_events"
        ).fetchone()[0]

        threats = conn.execute(
            "SELECT COUNT(*) FROM security_events WHERE is_threat = 1"
        ).fetchone()[0]

        severity_rows = conn.execute("""
            SELECT severity, COUNT(*)
            FROM security_events
            GROUP BY severity
        """).fetchall()

    return {
        "total_events": total,
        "detected_threats": threats,
        "normal_events": total - threats,
        "severity_breakdown": {
            row[0]: row[1] for row in severity_rows
        }
    }


if __name__ == "__main__":
    initialize_db()
    print("AEGIS-AI database initialized successfully!")
    print("Database location:", DB_PATH)