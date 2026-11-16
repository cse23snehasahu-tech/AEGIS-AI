# AEGIS-AI
## AI-Powered Cloud Security Threat Detection and Intelligent Response System

### Major Project Report

**Submitted by:** Sneha Sahu  
**Degree:** Bachelor of Technology  
**Branch:** Computer Science and Engineering  
**Project Domain:** Artificial Intelligence, Machine Learning and Cybersecurity

---

## 1. Abstract

AEGIS-AI is an AI-based security monitoring prototype designed to identify suspicious activities in security event data. It uses machine learning techniques to classify potentially malicious events, detect unusual behaviour, calculate risk scores, and recommend suitable security responses.

The system uses a Random Forest Classifier for suspicious activity classification and Isolation Forest for anomaly detection. A risk-scoring module evaluates the severity of detected events, while an intelligent response module provides recommendations.

A Flask REST API supports backend operations, SQLite stores analyzed events, and a Streamlit dashboard provides an interactive interface for monitoring and analysis.

The project demonstrates how artificial intelligence and machine learning can support security event analysis and decision-making.

## 2. Introduction

Cybersecurity is an important requirement for modern organizations that depend on digital infrastructure and cloud-based services. Security events such as repeated login failures, unusual access locations, suspicious IP addresses, and unexpected data transfers may indicate potential security threats.

Manual analysis of large numbers of security events can be time-consuming. AEGIS-AI aims to simplify this process by using machine learning models and automated risk analysis to identify potentially suspicious activities.

The project is developed as a local academic prototype using synthetic security event data.

## 3. Problem Statement

Traditional security monitoring may require continuous manual examination of security logs. Identifying unusual activities and deciding their severity can become difficult when event volumes increase.

The proposed system addresses this challenge by:
- Analyzing security event attributes.
- Identifying suspicious activities.
- Detecting anomalous behaviour.
- Calculating event risk scores.
- Recommending appropriate security actions.
- Maintaining a history of analyzed events.

## 4. Objectives

1. Develop an AI-based security event detection system.
2. Apply machine learning for threat classification.
3. Detect unusual activities using anomaly detection.
4. Calculate risk scores based on security indicators.
5. Generate intelligent security recommendations.
6. Store analyzed events in a database.
7. Provide an interactive security monitoring dashboard.

## 5. Proposed System

AEGIS-AI consists of the following major modules:

**5.1 Data Generation and Preprocessing**

A synthetic dataset containing 10,000 security events is generated. Data preprocessing handles missing values, duplicate records, and feature engineering.

**5.2 Threat Detection**

The system uses:
- Random Forest Classifier for suspicious activity classification.
- Isolation Forest for anomaly detection.

**5.3 Risk Scoring**

A risk-scoring module calculates a score between 0 and 100 based on suspicious security indicators.

**5.4 Intelligent Response**

The system generates recommendations based on detected conditions, including suspicious login attempts, poor IP reputation, unusual locations, risky devices, and abnormal data transfers.

**5.5 Database Management**

SQLite stores event details, detection results, risk information, and response recommendations.

**5.6 Backend API**

Flask provides REST API endpoints for health checks, event analysis, event history, and statistics.

**5.7 Dashboard**

Streamlit provides an interactive dashboard to analyze security events, view threat history, and examine model insights.

## 6. System Architecture

The system follows this processing flow:

Security Event Data  
↓  
Data Preprocessing  
↓  
Machine Learning Models  
↓  
Threat Detection and Anomaly Analysis  
↓  
Risk Scoring  
↓  
Intelligent Response Recommendations  
↓  
SQLite Database  
↓  
Streamlit Dashboard and Flask API

## 7. Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core programming |
| Pandas and NumPy | Data processing |
| Scikit-learn | Machine learning |
| Random Forest | Threat classification |
| Isolation Forest | Anomaly detection |
| Flask | REST API |
| Streamlit | Interactive dashboard |
| SQLite | Database |
| Plotly | Data visualization |
| Joblib | Model persistence |

## 8. Dataset Description

The project uses a synthetically generated dataset containing 10,000 records and 13 original columns.

Important attributes include:
- Login attempts
- Failed logins
- Access hour
- Data transfer volume
- IP reputation
- Privilege level
- Unusual location
- Access denied count
- Session duration
- Device risk
- Suspicious activity label
- Event type

The preprocessing module creates additional engineered features for model analysis.

The dataset contains:
- Normal events: 6,423
- Suspicious events: 3,577

The target labels are generated using predefined rules. Therefore, the dataset is suitable for demonstrating the system workflow but does not represent real-world cloud security telemetry.

## 9. Machine Learning Algorithms

### 9.1 Random Forest Classifier

Random Forest is an ensemble learning algorithm that combines multiple decision trees to make predictions.

In AEGIS-AI, it classifies security events as normal or suspicious.

### 9.2 Isolation Forest

Isolation Forest is an unsupervised anomaly detection algorithm. It identifies observations that differ significantly from normal patterns.

In this project, it provides an additional anomaly detection signal.

## 10. Model Evaluation

The trained models produced the following results on the synthetic dataset:

| Metric | Random Forest |
|---|---:|
| Accuracy | 99.95% |
| Precision | 99.86% |
| Recall | 100% |
| F1 Score | 99.93% |
| ROC-AUC | 1.00 |

Isolation Forest results:

| Metric | Isolation Forest |
|---|---:|
| Precision | 50.25% |
| Recall | 69.09% |
| F1 Score | 58.19% |

**Evaluation Note:** The Random Forest model's high scores are expected because the synthetic target labels were generated using predefined rules. These results do not establish real-world threat detection performance. Further evaluation on representative real security data is necessary.

## 11. Risk Classification

The system assigns risk levels using its risk-scoring module.

| Risk Score | Severity |
|---|---|
| 0 | Minimal |
| 1–34 | Low |
| 35–59 | Medium |
| 60–79 | High |
| 80–100 | Critical |

The risk score is calculated using security indicators and detection results.

## 12. Intelligent Response Mechanism

Based on the detected event and risk level, the system recommends actions such as:
- Investigating repeated failed login attempts.
- Verifying suspicious IP addresses.
- Performing additional identity verification.
- Investigating high-risk devices.
- Reviewing unusual data transfers.
- Auditing privileged account activity.
- Escalating critical security events.

The current implementation provides recommendations only. It does not automatically execute blocking or isolation actions.

## 13. Database and API

SQLite is used to maintain a persistent record of analyzed security events.

The Flask API provides the following endpoints:

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | API information |
| `/health` | GET | API health check |
| `/analyze` | POST | Analyze security events |
| `/events` | GET | Retrieve event history |
| `/stats` | GET | Retrieve security statistics |

## 14. Results and Output

The system was tested with both normal and suspicious security events.

A sample suspicious event containing repeated failed logins, low IP reputation, unusual location, high data transfer, and high device risk produced:

- Detection status: Suspicious
- Risk score: 100/100
- Severity: Critical
- Threat status: True
- Response mode: Recommendation Only

The event was successfully stored in the SQLite database and displayed in the dashboard's event history.

## 15. Advantages

- Combines classification and anomaly detection.
- Provides risk-based security analysis.
- Generates understandable response recommendations.
- Maintains event history.
- Offers an interactive dashboard.
- Uses modular architecture for future development.

## 16. Limitations

- Uses synthetic rather than live cloud security data.
- Does not currently integrate with AWS CloudTrail or GuardDuty.
- Does not execute automatic security actions.
- Model performance requires validation on real-world datasets.
- The current implementation is a local academic prototype.

## 17. Future Scope

- Integration with AWS CloudTrail and GuardDuty.
- Real-time cloud event monitoring.
- Advanced anomaly detection techniques.
- Explainable AI for improved threat interpretation.
- Email and notification-based security alerts.
- Role-based access control.
- Secure cloud deployment.

## 18. Conclusion

AEGIS-AI demonstrates the application of machine learning, risk scoring, anomaly detection, and intelligent response recommendations in cybersecurity.

The system provides a modular prototype that can analyze synthetic security events, identify suspicious activities, assign risk levels, and display results through an interactive dashboard.

The project establishes a foundation for future development involving real cloud telemetry, advanced security analytics, and production-level deployment.

## 19. References

1. Scikit-learn Documentation — https://scikit-learn.org/
2. Flask Documentation — https://flask.palletsprojects.com/
3. Streamlit Documentation — https://docs.streamlit.io/
4. Pandas Documentation — https://pandas.pydata.org/docs/
5. NumPy Documentation — https://numpy.org/doc/
6. Python Documentation — https://docs.python.org/3/

---

**Project Title:** AEGIS-AI  
**Project Author:** Sneha Sahu  
**Domain:** AI, Machine Learning and Cybersecurity