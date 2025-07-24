# Cyber Actuarial Financial Risk Simulator

This project simulates and analyzes cyber risk using actuarial and data science techniques. It ingests threat intelligence feeds, parses logs, detects anomalies, and simulates financial risk, providing an interactive dashboard for visualization.

## Features

- Ingests threat intelligence and log data
- Anomaly detection using machine learning
- Cyber risk simulation and financial impact analysis
- Interactive dashboard built with Flask and Plotly

## Structure

- `data_ingestion/`: Data collection and parsing modules
- `analytics/`: Anomaly detection and risk simulation
- `dashboard/`: Flask app and dashboard templates
- `config.py`: API keys and configuration

## Setup

1. Install dependencies: `pip install -r requirements.txt`
2. Configure API keys in `config.py`
3. Run the dashboard: `python dashboard/app.py`

## Blockchain Audit Logger

A simple blockchain-based audit logger is implemented in `blockchain/audit_logger.py` using Python's hashlib. It provides:

- `add_block(event_data)`: Add an event to the blockchain ledger
- `verify_chain()`: Verify the integrity of the blockchain

This logger is integrated with `data_ingestion/threat_feeds.py` to log threat feed events for tamper-evident auditing.
