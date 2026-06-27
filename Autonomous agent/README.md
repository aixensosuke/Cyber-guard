# CyberGuard-IR: Offline Autonomous Incident Response Agent

CyberGuard-IR is an offline, production-grade security orchestration, automation, and response (SOAR) system. It ingests raw logs, normalizes them, detects multi-stage threats using an unsupervised Machine Learning ensemble, maps activities to the MITRE ATT&CK kill chain using entity graphs, prioritizes incidents via a Composite Fidelity Ranking (CFR) score, and generates step-by-step containment playbooks using LangGraph and localized LLMs.

The entire system runs **100% offline** (zero external APIs/data transfers), satisfying strict banking regulatory compliance frameworks (RBI CSCRF, EU DORA, and PCI-DSS).

---

## 🏗️ 7-Layer Architecture Pipeline

1. **Ingestion & Normalization:** Translates arbitrary inputs (Active Directory, SSH logins, proxy events) into a unified JSON Pydantic schema (`CanonicalEvent`) while deduplicating repeating events.
2. **Persistence:** Connects to a local Elasticsearch cluster via Docker, falling back automatically to a local SQLite database (`cyberguard.db`) for lightweight development.
3. **Anomaly Detection:** An unsupervised ensemble utilizing scikit-learn preprocessing and PyOD models (**Isolation Forest** + **Local Outlier Factor**) to flag statistical outliers.
4. **Behavioral Analytics (UEBA):** Builds historical hourly metrics (e.g. data transfer volumes, log counts) and calculates Z-scores and novelty flags (new processes/destination IPs) per host and user.
5. **Correlation & Kill-Chain:** Construct NetworkX directed entity relationship graphs to link users, IPs, ports, and files. Collapses isolated anomalies into consolidated incidents and maps signatures to MITRE ATT&CK stages.
6. **Fidelity Ranking (CFR):** Evaluates threat criticality from `0.0` to `10.0` using a composite score weighting ML scores, UEBA deviations, graph size, MITRE progress, and asset criticality tiers.
7. **Orchestration & Response:** State-machine control flow powered by **LangGraph** and **FastMCP** containment tools. Queries a local Ollama LLM (falling back to a smart mock template generator if offline) to construct actionable playbooks.

---

## 📋 Banking Compliance Mapping

* **RBI CSCRF (Annex I, Sec 3):** All incident assessments, raw log linkages, and containment outcomes are logged immutably in a structured audit log (`cyberguard.audit.log`).
* **EU DORA (Article 17 & 18):** Identifies and groups events into "Major ICT-Related Incidents" based on privilege compromises and exfiltration volumes.
* **PCI-DSS (Req 12.10):** Restricts outbound data exfiltrations and initiates automated, auditable quarantines via FastMCP tools.

---

## 🚀 Setup & Execution

### 1. Prerequisites
* Python 3.11
* Optional: Docker (for Elasticsearch)

### 2. Install Dependencies
```bash
python -m pip install -r requirements.txt
```

### 3. Spin Up Storage (Elasticsearch)
If you wish to use Elasticsearch:
```bash
docker-compose up -d
```
*(If Docker is not running, the system will seamlessly run and store events inside `cyberguard.db` SQLite database).*

### 4. Run the Pipeline Demo
To run the end-to-end incident response lifecycle (which creates 250 baseline events and runs a simulated SSH brute force and data exfiltration attack):
```bash
python run_pipeline.py
```

### 5. Run the Test Suite
Verify component logic and integrations using pytest:
```bash
pytest -v
```
