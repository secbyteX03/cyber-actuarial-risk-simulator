"""
Module for parsing log files.
"""

import re
import pandas as pd
from datetime import datetime, timedelta

class LogParser:
    # Regex for common Apache/NGINX log format
    LOG_PATTERN = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - '\
        r'\[(?P<timestamp>[^\]]+)\] '\
        r'"(?P<method>\w+) (?P<endpoint>[^ ]+) [^"]+" '\
        r'(?P<status>\d{3})'
    )

    def __init__(self, log_lines):
        """
        log_lines: list of log lines (strings)
        """
        self.log_lines = log_lines
        self.parsed = []
        self.df = None

    def parse_logs(self):
        """
        Parse log lines and extract IP, timestamp, endpoint, status code.
        """
        for line in self.log_lines:
            match = self.LOG_PATTERN.search(line)
            if match:
                data = match.groupdict()
                # Convert timestamp to datetime
                try:
                    data['timestamp'] = datetime.strptime(data['timestamp'], '%d/%b/%Y:%H:%M:%S %z')
                except Exception:
                    data['timestamp'] = None
                data['status'] = int(data['status'])
                self.parsed.append(data)
        self.df = pd.DataFrame(self.parsed)
        return self.df

    def detect_brute_force(self, fail_statuses={401, 403, 404}, threshold=5, window_minutes=1):
        """
        Detect brute-force attempts: >threshold failed logins from same IP in window_minutes.
        Returns DataFrame of suspicious IPs and counts.
        """
        if self.df is None:
            self.parse_logs()
        df = self.df
        if df.empty:
            return pd.DataFrame()
        # Filter failed login attempts
        failed = df[df['status'].isin(fail_statuses)].copy()
        failed = failed.dropna(subset=['timestamp'])
        # Sort by IP and timestamp
        failed = failed.sort_values(['ip', 'timestamp'])
        suspicious = []
        for ip, group in failed.groupby('ip'):
            times = group['timestamp'].tolist()
            for i in range(len(times)):
                window = [t for t in times if t >= times[i] and t < times[i] + timedelta(minutes=window_minutes)]
                if len(window) > threshold:
                    suspicious.append({'ip': ip, 'count': len(window), 'window_start': times[i]})
                    break  # Only report once per IP
        return pd.DataFrame(suspicious)

    def save_to_dataframe(self):
        """
        Return the parsed log data as a Pandas DataFrame.
        """
        if self.df is None:
            self.parse_logs()
        return self.df 