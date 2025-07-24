from flask import Flask, render_template, jsonify
import numpy as np
import plotly.graph_objs as go
import plotly.io as pio
from analytics import risk_simulation
from analytics import anomaly_detection
from data_ingestion.threat_feeds import ThreatFeedIngester
import pandas as pd

app = Flask(__name__)

# Mock API keys and ingester for demonstration
API_KEYS = {
    'VIRUSTOTAL_API_KEY': 'demo',
    'IBM_X_FORCE_API_KEY': 'demo'
}
threat_ingester = ThreatFeedIngester(API_KEYS)

# Mock threat data and losses for demonstration
MOCK_THREAT_DATA = threat_ingester.get_all_feeds()
MOCK_LOSSES = np.random.lognormal(mean=10, sigma=1, size=10000)
MOCK_VAR = risk_simulation.calculate_var(MOCK_LOSSES, confidence_level=0.95)
MOCK_EXPECTED_LOSS = np.mean(MOCK_LOSSES)
MOCK_RISK_SCORES = np.random.rand(100)
MOCK_ALERTS = list(np.where(MOCK_RISK_SCORES > 0.8)[0])

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/threat-data')
def api_threat_data():
    # Return latest threat feed JSON (mocked)
    return jsonify(MOCK_THREAT_DATA)

@app.route('/api/risk-metrics')
def api_risk_metrics():
    # Return VaR and expected loss (mocked)
    return jsonify({
        'value_at_risk': float(MOCK_VAR),
        'expected_loss': float(MOCK_EXPECTED_LOSS)
    })

@app.route('/api/alerts')
def api_alerts():
    # Return active anomalies (mocked)
    return jsonify({'active_alerts': MOCK_ALERTS})

@app.route('/api/risk-chart')
def api_risk_chart():
    # Return a Plotly histogram of simulated losses (as JSON)
    fig = go.Figure(data=[go.Histogram(x=MOCK_LOSSES, nbinsx=50)])
    fig.update_layout(title='Simulated Loss Distribution', xaxis_title='Loss', yaxis_title='Frequency')
    chart_json = pio.to_json(fig)
    return chart_json

if __name__ == '__main__':
    app.run(debug=True) 