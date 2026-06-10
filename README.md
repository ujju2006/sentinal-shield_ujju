# SentinelShield SOC & WAF Educational Platform

SentinelShield is an advanced, Python-based Web Application Firewall (WAF) middleware and Security Operations Center (SOC) dashboard. It is designed as a hybrid enterprise-grade security tool and an interactive educational platform for cybersecurity students.

## Features

- **Live Request Monitoring:** Real-time logging and interception of incoming HTTP traffic.
- **Intrusion Detection System (WAF):** Detects and blocks common web vulnerabilities including SQL Injection (SQLi), Cross-Site Scripting (XSS), Directory Traversal (LFI), and Volumetric / Brute-Force attacks.
- **Dynamic IP Threat Intelligence:** Tracks IP reputation and automatically throttles or blocks malicious actors based on behavioral analysis.
- **Educational Forensic Analysis:** Transforms raw security logs into highly detailed, 11-section analyst reports complete with MITRE/OWASP mappings, attacker objectives, and developer prevention guides.
- **WAF Simulation Lab:** A built-in penetration testing interface with a live terminal to simulate attacks and visualize WAF defenses in real-time.
- **PDF Export:** One-click generation of professional security posture and forensic incident reports.

## Technology Stack

- **Backend:** Python, Flask, Werkzeug
- **Frontend:** HTML5, CSS3, Vanilla JavaScript
- **Charting:** Chart.js
- **Exports:** html2pdf.js

## Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/SentinelShield.git
   cd SentinelShield
   ```

2. **Install dependencies:**
   Ensure you have Python 3 installed. Install the required packages:
   ```bash
   pip install flask werkzeug
   ```

3. **Run the Application:**
   ```bash
   python app.py
   ```
   The application will start on `http://localhost:5000`.

## Usage

- **Login / Signup:** Create a local analyst account to access the dashboard.
- **Dashboard:** View live traffic, IP behavior, and system logs.
- **Analysis Tools:** Paste raw URLs or IP addresses into the Investigation Engine for instant threat analysis.
- **Simulation Lab:** Access the `/test` endpoint to simulate botnet traffic, credential stuffing, and injection flaws against the WAF.

## Educational Value
SentinelShield was built specifically to bridge the gap between raw server logs and human-readable security analysis. It serves as an automated mentor, explaining *why* an attack occurred and *how* to prevent it, rather than just outputting a block event.

## License
MIT License
