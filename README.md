# Aegis Vulns

Aegis Vulns is a vulnerability and threat-intelligence aggregation dashboard that pulls from multiple public sources (CISA KEV, URLhaus, and security news RSS) and normalizes everything into a single analyst-style feed for quick triage.

This project is actively in development and is part of an ongoing security research and tooling effort.  
Features, scoring logic, and data sources are continuously evolving as the platform expands.

## What This Project Does

This tool is meant to answer one simple question:  
“What security items should I care about right now, and what should I do first?”

It ingests:
- Known exploited vulnerabilities (CISA KEV)
- Live malware / phishing indicators (URLhaus)
- Security incident reporting and threat news (RSS)

Then it:
- Normalizes and deduplicates entries
- Adds lightweight categorization and OS inference
- Assigns a basic urgency score for sorting
- Provides quick “so what / who cares / what to do” triage context

## Running the Project & Current State

This project is actively in development and is part of an ongoing security research and tooling effort.  
Features, scoring logic, and data sources are continuously evolving as the platform expands.

### Current Capabilities
- Live vulnerability ingestion from public feeds (CISA KEV)
- Malware and phishing URL monitoring (URLhaus)
- Threat news ingestion (BleepingComputer RSS)
- Normalization + deduplication across sources
- Threat categorization and basic risk scoring
- OS inference (Windows / Linux / MacOS / Network / Cross-Platform)
- Analyst-oriented triage context (“who should care” + “what to do now”)
- Web-based dashboard for centralized visibility
- Optional AI “Explain this” feature for short human-readable summaries (if enabled)

### Planned Improvements
- Persistent storage and historical tracking
- Authentication and multi-user support
- IOC export (CSV/JSON) and integration workflows
- Correlation with security telemetry / logs
- Risk trend tracking over time (charts + deltas)
- Better enrichment (CVE -> EPSS/CVSS, vendor advisory links, etc.)
- Tagging and saved views for SOC-style workflows

### How to Run
After installing dependencies listed in `requirements.txt`:

- `pip install -r requirements.txt`
- `python app.py`

Then open:
- http://127.0.0.1:5000

## What `pip install -r requirements.txt` Means

`requirements.txt` is just a list of Python packages this project depends on (Flask, requests, feedparser, etc.).  
That command tells pip: “Install everything listed in that file.”

## AI Feature (Optional)

This project includes an optional AI explanation endpoint:

- `POST /api/ai_explain`

If `OPENAI_API_KEY` is set in your environment, the app can generate a short, practitioner-friendly summary of a selected item (what it is, who cares, what to do now, why it matters).

If the key is not set, the rest of the project still works normally.

## Data Sources

- CISA Known Exploited Vulnerabilities (KEV)
- URLhaus recent malicious URLs API
- BleepingComputer RSS feed

## Notes

- This is a research / portfolio project and is continuously evolving.
- Scoring and inference are intentionally lightweight right now; the goal is fast triage, not perfect classification.
