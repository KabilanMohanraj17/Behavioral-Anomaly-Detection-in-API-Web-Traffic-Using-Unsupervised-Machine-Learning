# 🛡️ API-Sentinel: AI-Powered API Security & Log Analyzer

> An offline, machine-learning log analyzer that detects zero-day API threats through behavioral anomaly detection and spatial geometry mapping.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![Scikit-Learn](https://img.shields.io/badge/scikit--learn-Machine%20Learning-orange?logo=scikit-learn&logoColor=white)
![Pandas](https://img.shields.io/badge/Pandas-Data%20Processing-150458?logo=pandas&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 📖 Overview

Traditional Web Application Firewalls (WAFs) rely on semantic analysis and static signatures to block known threats. However, they frequently fail against novel Zero-Day exploits and "low and slow" reconnaissance attacks. 

**API-Sentinel** takes a different approach. Instead of reading the *text* of an attack, it maps the *physical geometry* of the network traffic. By leveraging an Unsupervised Machine Learning model (**Isolation Forest**), it establishes a mathematical baseline of standard user behavior. When an attacker attempts a massive SQL Injection, Cross-Site Scripting (XSS), or Buffer Overflow, the spatial dimensions of their request (URL length, payload mass) force them outside the normal "gravity well" of traffic, isolating them instantly.

---

## ✨ Key Features

* 🧠 **Unsupervised Zero-Day Detection:** Finds threats without needing a database of known malware signatures.
* 🗣️ **Explainable AI (XAI):** Doesn't just block traffic—it generates human-readable contextual reports explaining *why* a request is anomalous (e.g., "URL is 14x larger than baseline").
* 🕵️ **Offline Threat Hunting:** Processes large batch logs to catch "low and slow" attacks that evade real-time WAF memory windows.
* ⚡ **High-Speed Triage:** Reduces SOC (Security Operations Center) alert fatigue by highlighting only mathematically isolated anomalies.

---

## 🏗️ System Architecture

```text
+-------------------+       +-----------------------+       +-------------------------+
|                   |       |   Feature Extraction  |       |   Unsupervised Model    |
|  Raw HTTP/API     | ----> |  - url_length         | ----> |   (Isolation Forest)    |
|  Server Logs      |       |  - payload_size       |       |   Finds Spatial Outliers|
|  (.csv format)    |       |  - method_encoded     |       |                         |
+-------------------+       +-----------------------+       +-------------------------+
                                                                        |
                                                                        v
+-------------------+       +-----------------------+       +-------------------------+
|  SOC Analyst      |       |  Explainable AI (XAI) |       |  Anomaly Scoring        |
|  Dashboard /      | <---- |  Human-Readable       | <---- |  Normal: 1              |
|  Terminal Output  |       |  Threat Reports       |       |  Anomaly: -1            |
+-------------------+       +-----------------------+       +-------------------------+
```

---

## ⚙️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/yourusername/api-sentinel.git](https://github.com/yourusername/api-sentinel.git)
   cd api-sentinel
   ```

2. **Create a virtual environment (Recommended):**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install required dependencies:**
   ```bash
   pip install pandas scikit-learn joblib
   ```

---

## 🚀 Usage
DATASET USED : CSIC 2010 Web Application Attacks from kaggle(for industrial setup the model will be trained with industry logs)

Ensure you have your trained model files (`api_sentinel_model.pkl` and `method_encoder.pkl`) in the same directory as the script. 

Run the analyzer via the command line, passing the target log file as an argument:

```bash
python detect.py demo_logs.csv
```

---

## 🔬 Technical Details & Feature Engineering

The model currently evaluates three primary mathematical features:

1. **`url_length`**: Measures the character length of the endpoint. Normalizes baseline GET requests. Massive spikes reliably indicate URL-based injection attacks.
2. **`lenght` (Payload Size)**: Measures the byte mass of the request body. Normal POST requests form a baseline mass; massive spikes indicate Buffer Overflow attempts or data exfiltration.
3. **`method_encoded`**: Uses a LabelEncoder to translate HTTP verbs into categorical integers, detecting verb tampering.

---

## ⚠️ Limitations & Future Scope

* **Feature Blindness to Time:** The current model evaluates requests independently. Future updates will include `request_velocity` to catch Credential Stuffing and Business Logic Abuse.
* **Local Baseline Requirement:** Deploying this model in a new enterprise environment requires a "Shadow Mode" period to retrain on local traffic and prevent False Positives.
* **Sequential Modeling:** Future iterations will integrate Markov Chains to track user session flows and catch out-of-order API endpoint access.

---

## 👨‍💻 Author

**Kabilan Mohanraj** 
* [LinkedIn](www.linkedin.com/in/kabilan-mohanraj-357a58320)

