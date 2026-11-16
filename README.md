# AEGIS-AI
### AI-Powered Cloud Security Threat Detection and Intelligent Response System

AEGIS-AI is an academic AI-based security monitoring prototype designed to analyze security events, identify suspicious activities, calculate risk levels, and recommend appropriate security responses.

The system combines machine learning models, risk scoring, and an interactive dashboard to help users understand potentially suspicious security events.

## Key Features

- **AI-Based Threat Detection:** Uses Random Forest classification and Isolation Forest anomaly detection.
- **Risk Scoring:** Calculates a risk score between 0 and 100.
- **Threat Severity:** Categorizes events into Minimal, Low, Medium, High, and Critical levels.
- **Intelligent Response:** Provides recommendations based on detected security conditions.
- **Security Dashboard:** Displays event statistics, threat history, charts, and model insights.
- **REST API:** Flask-based endpoints for health checks, event analysis, and statistics.
- **Database Storage:** Stores analyzed security events using SQLite.

## Technologies Used

| Category | Technologies |
|---|---|
| Programming Language | Python |
| Machine Learning | Scikit-learn |
| Data Processing | Pandas, NumPy |
| Backend | Flask |
| Frontend / Dashboard | Streamlit |
| Visualization | Plotly |
| Database | SQLite |
| Model Storage | Joblib |

## System Architecture

1. Security events are generated as a synthetic dataset.
2. Data preprocessing cleans the data and creates additional features.
3. Machine learning models analyze the security events.
4. The risk-scoring module calculates risk levels.
5. The intelligent response module generates recommended actions.
6. Results are stored in SQLite.
7. The Streamlit dashboard presents the analysis.

## Machine Learning Models

**Random Forest Classifier**
- Used for suspicious activity classification.
- Accuracy: 99.95%
- Precision: 99.86%
- Recall: 100%
- F1 Score: 99.93%
- ROC-AUC: 1.00

**Isolation Forest**
- Used for anomaly detection.
- Precision: 50.25%
- Recall: 69.09%
- F1 Score: 58.19%

**Important:** The dataset is synthetically generated, and its labels are created using predefined rules. Therefore, the high Random Forest performance reflects the synthetic dataset's patterns and should not be interpreted as proven real-world security detection accuracy.

## Project Structure

```text
AEGIS_AI/
│
├── dataset/
│   ├── generate_dataset.py
│   ├── security_events.csv
│   └── processed_events.csv
│
├── models/
│   ├── random_forest_model.pkl
│   ├── isolation_forest_model.pkl
│   └── feature_names.pkl
│
├── modules/
│   ├── data_preprocessing.py
│   ├── train_models.py
│   ├── threat_detection.py
│   ├── risk_scoring.py
│   └── intelligent_response.py
│
├── database/
│   ├── db_manager.py
│   └── aegis_security.db
│
├── reports/
│   ├── model_metrics.csv
│   └── feature_importance.csv
│
├── screenshots/
│
├── api.py
├── app.py
└── README.md
```

## Installation and Execution

**1. Clone the repository**

```bash
git clone https://github.com/cse23snehasahu-tech/AEGIS-AI.git
cd AEGIS-AI
```

**2. Create and activate a virtual environment**

```bash
python -m venv venv
```

Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

**3. Install dependencies**

```bash
pip install numpy pandas scikit-learn flask streamlit plotly matplotlib seaborn joblib
```

**4. Run the Flask API**

```bash
python api.py
```

API base URL: `http://127.0.0.1:5000`

**5. Run the Streamlit dashboard**

Open another terminal in the project directory, activate the virtual environment, and run:

```bash
python -m streamlit run app.py
```

Dashboard URL: `http://localhost:8501`

## API Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/` | GET | API information |
| `/health` | GET | Health check |
| `/analyze` | POST | Analyze a security event |
| `/events` | GET | Retrieve event history |
| `/stats` | GET | Retrieve security statistics |

## Current Limitations

- Uses synthetic security event data rather than live cloud telemetry.
- Cloud integrations such as AWS CloudTrail and GuardDuty are not currently implemented.
- Security actions are recommendations only; the system does not automatically block accounts, IP addresses, or devices.
- Model performance must be validated on representative real-world security data before practical deployment.

## Future Enhancements

- AWS CloudTrail integration.
- Real-time cloud security monitoring.
- Advanced anomaly detection.
- Explainable AI for security decisions.
- Alert notifications and incident reporting.
- Secure role-based dashboard access.

## Author

**Sneha Sahu**

B.Tech – Computer Science and Engineering

GitHub: [cse23snehasahu-tech](https://github.com/cse23snehasahu-tech)

---

*AEGIS-AI is developed as an academic major project to demonstrate the application of machine learning, backend development, database management, and security analytics.*