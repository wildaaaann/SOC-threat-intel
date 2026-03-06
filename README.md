# 🛡️ SOC Threat Intelligence AI Dashboard

An automated, AI-powered Threat Intelligence gathering and reporting dashboard built for Security Operations Center (SOC) Analysts. 

This tool drastically reduces the time spent on manual IoC (Indicator of Compromise) investigation by automatically querying multiple Threat Intelligence platforms, aggregating the raw JSON data, and utilizing **Google Gemini AI** to synthesize the findings into a clear, standardized, and ready-to-copy SOC ticket report.

## ✨ Features

- **Multi-Source Intel Gathering:** Automatically queries VirusTotal, AbuseIPDB, URLScan, and HybridAnalysis based on the IoC type.
- **Smart IoC Detection:** Automatically detects whether the input is an IPv4, Domain, MD5, SHA1, or SHA256.
- **AI-Powered Synthesis:** Uses `gemini-2.5-flash` to parse complex JSON relationship data and write a human-readable narrative.
- **Auto-Defanging:** Ensures all malicious domains in the final report are defanged (e.g., `example[.]com`) for safe ticketing (OPSEC).
- **Session History:** Keeps track of your analysis history during the active session without storing sensitive data permanently on the server.
- **Failsafe Mechanism:** If the AI API hits a rate limit (Error 429), the app provides a one-click download for the collated raw prompt, allowing analysts to process it manually.

## 🛠️ Prerequisites

To run this application, you will need the following API Keys:
1. **Google Gemini API Key** (Mandatory)
2. **VirusTotal API Key** (Mandatory)
3. **AbuseIPDB API Key** (Mandatory)
4. **URLScan API Key** (Optional)
5. **HybridAnalysis API Key** (Optional)

## 🚀 Installation & Setup (Local Environment)

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/](https://github.com/)wildaaaann/SOC-threat-intel.git
   cd SOC-threat-intel
