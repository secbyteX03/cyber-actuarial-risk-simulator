import os
from flask import Flask, render_template, jsonify, request, redirect, url_for
import numpy as np
import plotly.graph_objs as go
import plotly.io as pio
from analytics import risk_simulation
from analytics import anomaly_detection
from data_ingestion.threat_feeds import ThreatFeedIngester
import pandas as pd
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, login_required, roles_required, hash_password, current_user
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_bcrypt import Bcrypt
from flask_dance.contrib.keycloak import make_keycloak_blueprint, keycloak
from dotenv import load_dotenv

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

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'super-secret')
app.config['SECURITY_PASSWORD_SALT'] = os.getenv('SECURITY_PASSWORD_SALT', 'super-salt')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///security.db')
app.config['SECURITY_PASSWORD_HASH'] = 'bcrypt'
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'jwt-secret-string')
app.config['SECURITY_REGISTERABLE'] = True
app.config['SECURITY_SEND_REGISTER_EMAIL'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Content Security Policy
@app.after_request
def set_csp(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none';"
    return response

# Rate Limiting
limiter = Limiter(get_remote_address, app=app, default_limits=["100 per hour"])

# Database
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Define models
roles_users = db.Table('roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    fs_uniquifier = db.Column(db.String(255), unique=True, nullable=False)
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))

# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

# Setup JWT
jwt = JWTManager(app)

# OAuth2 SSO (Keycloak example)
keycloak_bp = make_keycloak_blueprint(
    server_url=os.getenv('KEYCLOAK_SERVER_URL', 'https://keycloak.example.com/auth/'),
    client_id=os.getenv('KEYCLOAK_CLIENT_ID', 'demo-client'),
    client_secret=os.getenv('KEYCLOAK_CLIENT_SECRET', 'demo-secret'),
    realm=os.getenv('KEYCLOAK_REALM', 'demo'),
    redirect_to='index'
)
app.register_blueprint(keycloak_bp, url_prefix="/login")


@app.route('/')
def index():
    return render_template('index.html')

# --- User Registration Endpoint (JWT) ---
@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'RiskAnalyst')  # Default role
    if not email or not password:
        return jsonify({'msg': 'Missing email or password'}), 400
    if user_datastore.find_user(email=email):
        return jsonify({'msg': 'User already exists'}), 400
    user = user_datastore.create_user(
        email=email,
        password=hash_password(password),
        fs_uniquifier=os.urandom(16).hex(),
        active=True
    )
    db.session.commit()
    # Assign role
    user_datastore.add_role_to_user(user, role)
    db.session.commit()
    return jsonify({'msg': 'User registered'}), 201

# --- User Login Endpoint (JWT) ---
@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = user_datastore.find_user(email=email)
    if not user or not user.verify_and_update_password(password):
        return jsonify({'msg': 'Bad credentials'}), 401
    if not user.active:
        return jsonify({'msg': 'User inactive'}), 403
    access_token = create_access_token(identity=user.id, additional_claims={'roles': [r.name for r in user.roles]})
    refresh_token = create_refresh_token(identity=user.id)
    return jsonify(access_token=access_token, refresh_token=refresh_token)

# --- Refresh Token Endpoint ---
@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    user = User.query.get(identity)
    access_token = create_access_token(identity=user.id, additional_claims={'roles': [r.name for r in user.roles]})
    return jsonify(access_token=access_token)

# --- Logout (JWT, stateless) ---
@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    # JWT is stateless; client should discard token
    return jsonify({'msg': 'Logged out'}), 200

# --- SSO Login/Logout (Keycloak) ---
@app.route('/sso')
def sso_login():
    if not keycloak.authorized:
        return redirect(url_for('keycloak.login'))
    resp = keycloak.get('/protocol/openid-connect/userinfo')
    if not resp.ok:
        return jsonify({'msg': 'Failed to fetch user info'}), 400
    info = resp.json()
    email = info.get('email')
    user = user_datastore.find_user(email=email)
    if not user:
        user = user_datastore.create_user(
            email=email,
            password=hash_password(os.urandom(16).hex()),
            fs_uniquifier=os.urandom(16).hex(),
            active=True
        )
        db.session.commit()
        user_datastore.add_role_to_user(user, 'RiskAnalyst')
        db.session.commit()
    access_token = create_access_token(identity=user.id, additional_claims={'roles': [r.name for r in user.roles]})
    refresh_token = create_refresh_token(identity=user.id)
    return jsonify(access_token=access_token, refresh_token=refresh_token)

@app.route('/sso/logout')
def sso_logout():
    token = keycloak.token['access_token'] if keycloak.authorized else None
    keycloak.token = None
    return redirect(url_for('index'))

# --- RBAC Decorator for JWT ---
def jwt_roles_required(*roles):
    def wrapper(fn):
        from functools import wraps
        @wraps(fn)
        @jwt_required()
        def decorator(*args, **kwargs):
            claims = get_jwt_identity()
            user = User.query.get(claims)
            user_roles = [r.name for r in user.roles]
            if not any(role in user_roles for role in roles):
                return jsonify({'msg': 'Insufficient role'}), 403
            return fn(*args, **kwargs)
        return decorator
    return wrapper

# --- Protect API Endpoints with RBAC ---
@app.route('/api/threat-data')
@jwt_roles_required('CISO', 'RiskAnalyst')
def api_threat_data():
    return jsonify(MOCK_THREAT_DATA)

@app.route('/api/risk-metrics')
@jwt_roles_required('CISO', 'RiskAnalyst')
def api_risk_metrics():
    return jsonify({
        'value_at_risk': float(MOCK_VAR),
        'expected_loss': float(MOCK_EXPECTED_LOSS)
    })

@app.route('/api/alerts')
@jwt_roles_required('CISO', 'RiskAnalyst', 'Auditor')
def api_alerts():
    return jsonify({'active_alerts': MOCK_ALERTS})

@app.route('/api/risk-chart')
@jwt_roles_required('CISO', 'RiskAnalyst')
def api_risk_chart():
    fig = go.Figure(data=[go.Histogram(x=MOCK_LOSSES, nbinsx=50)])
    fig.update_layout(title='Simulated Loss Distribution', xaxis_title='Loss', yaxis_title='Frequency')
    chart_json = pio.to_json(fig)
    return chart_json

# --- DB Init Instructions ---
# To initialize the database:
#   flask db init
#   flask db migrate
#   flask db upgrade
# To create roles:
#   with app.app_context():
#       for r in ['CISO', 'RiskAnalyst', 'Auditor']:
#           if not Role.query.filter_by(name=r).first():
#               db.session.add(Role(name=r))
#       db.session.commit()
#
# To create an admin user:
#   user_datastore.create_user(email='admin@example.com', password=hash_password('password'), fs_uniquifier='unique', active=True)
#   db.session.commit()
#   user_datastore.add_role_to_user(user, 'CISO')
#   db.session.commit()

if __name__ == '__main__':
    app.run(debug=True) 