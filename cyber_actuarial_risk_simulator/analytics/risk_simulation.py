"""
Module for simulating cyber risk and financial impact.
"""

import numpy as np


def monte_carlo_simulation(breach_likelihood, loss_distribution, iterations=10000):
    """
    Run Monte Carlo simulation for cyber loss events.
    breach_likelihood: probability of breach per iteration (float 0-1)
    loss_distribution: function returning a random loss amount
    iterations: number of simulations
    Returns: array of simulated losses
    """
    losses = []
    for _ in range(iterations):
        if np.random.rand() < breach_likelihood:
            loss = loss_distribution()
        else:
            loss = 0.0
            
        losses.append(loss)
    return np.array(losses)


def calculate_var(losses, confidence_level=0.95):
    """
    Calculate Value at Risk (VaR) at the given confidence level.
    losses: array-like of simulated losses
    confidence_level: e.g., 0.95 for 95%% VaR
    Returns: VaR value
    """
    return np.percentile(losses, 100 * confidence_level)


def bayesian_network_update(prior_prob, new_evidence):
    """
    Update probability using Bayes' theorem.
    prior_prob: prior probability (float)
    new_evidence: dict with 'likelihood' and 'evidence_prob'
    Returns: posterior probability
    """
    # P(A|B) = P(B|A) * P(A) / P(B)
    likelihood = new_evidence['likelihood']  # P(B|A)
    evidence_prob = new_evidence['evidence_prob']  # P(B)
    posterior = (likelihood * prior_prob) / evidence_prob if evidence_prob > 0 else prior_prob
    return posterior


def estimate_financial_impact(threat_type, base_loss=100000):
    """
    Estimate financial impact based on threat type.
    threat_type: string (e.g., 'ransomware', 'phishing', 'ddos')
    base_loss: base loss amount
    Returns: estimated loss
    """
    multipliers = {
        'ransomware': 2.5,
        'phishing': 1.2,
        'ddos': 1.5,
        'insider': 2.0,
        'malware': 1.7,
        'other': 1.0
    }
    multiplier = multipliers.get(threat_type.lower(), multipliers['other'])
    return base_loss * multiplier 