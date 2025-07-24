import os
import base64
import datetime
import secrets
from flask import current_app, session, make_response
from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt_identity, decode_token
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pyotp
import redis
from zxcvbn import zxcvbn
from .models import User, Role, APIToken, JWTRevocation
from .schemas import UserRegisterSchema, UserLoginSchema, MFAVerifySchema, APITokenSchema

REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
redis_client = redis.StrictRedis.from_url(REDIS_URL, decode_responses=True)

class AuthService:
    def __init__(self, db_session: Session, jwt_private_key: str, jwt_public_key: str):
        self.db = db_session
        self.jwt_private_key = jwt_private_key
        self.jwt_public_key = jwt_public_key
        self.jwt_alg = 'RS256'
        self.session_timeout = 900  # 15 min
        self.rate_limit_attempts = 10
        self.rate_limit_window = 300  # 5 min
        self.scrypt_n = 2**14
        self.scrypt_r = 8
        self.scrypt_p = 1
        self.salt_size = 32
        self.aes_key = os.getenv('MFA_AES_KEY', secrets.token_bytes(32))

    def hash_password(self, password: str) -> str:
        salt = os.urandom(self.salt_size)
        kdf = Scrypt(salt=salt, length=32, n=self.scrypt_n, r=self.scrypt_r, p=self.scrypt_p)
        key = kdf.derive(password.encode())
        return base64.b64encode(salt + key).decode()

    def verify_password(self, password: str, hashed: str) -> bool:
        data = base64.b64decode(hashed.encode())
        salt, key = data[:self.salt_size], data[self.salt_size:]
        kdf = Scrypt(salt=salt, length=32, n=self.scrypt_n, r=self.scrypt_r, p=self.scrypt_p)
        try:
            kdf.verify(password.encode(), key)
            return True
        except Exception:
            return False

    def register_user(self, data: dict) -> User:
        schema = UserRegisterSchema(**data)
        if self.db.query(User).filter_by(email=schema.email).first():
            raise ValueError('User already exists')
        hashed = self.hash_password(schema.password)
        user = User(email=schema.email, password=hashed, active=True)
        # Assign role
        role = self.db.query(Role).filter_by(name=schema.role).first()
        if not role:
            raise ValueError('Invalid role')
        user.roles.append(role)
        self.db.add(user)
        self.db.commit()
        return user

    def rate_limit_check(self, key: str):
        attempts = redis_client.get(key)
        if attempts and int(attempts) >= self.rate_limit_attempts:
            raise Exception('Too many attempts, try later')
        redis_client.incr(key)
        redis_client.expire(key, self.rate_limit_window)

    def login_user(self, data: dict) -> dict:
        schema = UserLoginSchema(**data)
        user = self.db.query(User).filter_by(email=schema.email).first()
        if not user or not self.verify_password(schema.password, user.password):
            self.rate_limit_check(f'login:{schema.email}')
            raise ValueError('Invalid credentials')
        if not user.active:
            raise ValueError('User inactive')
        # Session timeout
        user.last_active = datetime.datetime.utcnow()
        self.db.commit()
        access_token = create_access_token(identity=user.id, additional_claims={'roles': [r.name for r in user.roles]}, algorithm=self.jwt_alg, private_key=self.jwt_private_key)
        refresh_token = create_refresh_token(identity=user.id, algorithm=self.jwt_alg, private_key=self.jwt_private_key)
        return {'access_token': access_token, 'refresh_token': refresh_token}

    def revoke_jwt(self, jti: str):
        rev = JWTRevocation(jti=jti)
        self.db.add(rev)
        self.db.commit()

    def is_jwt_revoked(self, jti: str) -> bool:
        return self.db.query(JWTRevocation).filter_by(jti=jti).first() is not None

    def generate_api_token(self, user: User, scopes: list) -> str:
        token = base64.urlsafe_b64encode(os.urandom(32)).decode()
        api_token = APIToken(user_id=user.id, token=token, scopes=','.join(scopes))
        self.db.add(api_token)
        self.db.commit()
        return token

    def enable_mfa(self, user: User) -> str:
        secret = pyotp.random_base32()
        aesgcm = AESGCM(self.aes_key)
        nonce = os.urandom(12)
        enc_secret = nonce + aesgcm.encrypt(nonce, secret.encode(), None)
        user.mfa_secret_enc = enc_secret
        user.mfa_enabled = True
        # Generate recovery codes
        recovery_codes = [secrets.token_urlsafe(10) for _ in range(5)]
        enc_codes = nonce + aesgcm.encrypt(nonce, ','.join(recovery_codes).encode(), None)
        user.recovery_codes_enc = enc_codes
        self.db.commit()
        return secret

    def verify_mfa(self, user: User, code: str, recovery_code: str = None) -> bool:
        aesgcm = AESGCM(self.aes_key)
        nonce = user.mfa_secret_enc[:12]
        secret = aesgcm.decrypt(nonce, user.mfa_secret_enc[12:], None).decode()
        totp = pyotp.TOTP(secret)
        if code and totp.verify(code):
            return True
        if recovery_code:
            nonce = user.recovery_codes_enc[:12]
            codes = aesgcm.decrypt(nonce, user.recovery_codes_enc[12:], None).decode().split(',')
            if recovery_code in codes:
                # Remove used code
                codes.remove(recovery_code)
                new_enc = nonce + aesgcm.encrypt(nonce, ','.join(codes).encode(), None)
                user.recovery_codes_enc = new_enc
                self.db.commit()
                return True
        return False

    def set_secure_cookies(self, response, token):
        response.set_cookie('access_token', token, httponly=True, samesite='Strict', secure=True, max_age=self.session_timeout)
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response 