# Configuration file for API keys and other settings
import os

VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', 'your_virustotal_api_key_here')
IBM_X_FORCE_API_KEY = os.getenv('IBM_X_FORCE_API_KEY', 'your_ibm_x_force_api_key_here')

# Secure PostgreSQL connection string
POSTGRES_USER = os.getenv('POSTGRES_USER', 'postgres')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD', 'password')
POSTGRES_DB = os.getenv('POSTGRES_DB', 'cyber_risk_db')
POSTGRES_HOST = os.getenv('POSTGRES_HOST', 'localhost')
POSTGRES_PORT = os.getenv('POSTGRES_PORT', '5432')

SQLALCHEMY_DATABASE_URL = (
    f"postgresql+psycopg2://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
) 