"""
Module for ingesting threat intelligence feeds.
"""

import requests
import pandas as pd
import time
from ..blockchain.audit_logger import BlockchainLedger

class ThreatFeedIngester:
    def __init__(self, api_keys: dict, audit_logger: BlockchainLedger = None):
        """
        Initialize with a dictionary of API keys and optional audit logger.
        Example: {'VIRUSTOTAL_API_KEY': '...', 'IBM_X_FORCE_API_KEY': '...'}
        """
        self.api_keys = api_keys
        self.audit_logger = audit_logger

    def fetch_virustotal(self):
        """
        Fetch threat data from VirusTotal API. Returns JSON or mock data if unavailable.
        Logs the event to the blockchain audit logger if available.
        """
        url = 'https://www.virustotal.com/api/v3/files'
        headers = {'x-apikey': self.api_keys.get('VIRUSTOTAL_API_KEY', '')}
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            # Mock response for testing
            data = {
                'data': [
                    {'id': 'mock1', 'type': 'file', 'attributes': {'malicious': 1}},
                    {'id': 'mock2', 'type': 'file', 'attributes': {'malicious': 0}}
                ],
                'source': 'mock_virustotal',
                'error': str(e)
            }
        if self.audit_logger:
            self.audit_logger.add_block({
                'event': 'fetch_virustotal',
                'timestamp': time.time(),
                'result': 'success' if 'error' not in data else 'error',
                'details': data.get('error', None)
            })
        return data

    def fetch_ibm_xforce(self):
        """
        Fetch threat data from IBM X-Force API. Returns JSON or mock data if unavailable.
        Logs the event to the blockchain audit logger if available.
        """
        url = 'https://api.xforce.ibmcloud.com/malware'
        headers = {'Authorization': f'Bearer {self.api_keys.get("IBM_X_FORCE_API_KEY", "")}' }
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            # Mock response for testing
            data = {
                'malware': [
                    {'name': 'MockMalwareA', 'risk': 'high'},
                    {'name': 'MockMalwareB', 'risk': 'medium'}
                ],
                'source': 'mock_ibm_xforce',
                'error': str(e)
            }
        if self.audit_logger:
            self.audit_logger.add_block({
                'event': 'fetch_ibm_xforce',
                'timestamp': time.time(),
                'result': 'success' if 'error' not in data else 'error',
                'details': data.get('error', None)
            })
        return data

    def save_to_csv(self, data, filename):
        """
        Save a list of dicts or a dict with a list under a key to a CSV file.
        """
        # Try to extract list of records
        if isinstance(data, dict):
            # Try to find the first list in the dict
            for v in data.values():
                if isinstance(v, list):
                    data = v
                    break
        if not isinstance(data, list):
            raise ValueError('Data must be a list of records to save to CSV.')
        df = pd.DataFrame(data)
        df.to_csv(filename, index=False)

    def get_all_feeds(self):
        """
        Fetch all available threat feeds and return as a dict.
        """
        vt_data = self.fetch_virustotal()
        xforce_data = self.fetch_ibm_xforce()
        return {
            'virustotal': vt_data,
            'ibm_xforce': xforce_data
        } 