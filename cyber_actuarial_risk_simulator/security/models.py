from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime, LargeBinary, Index
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.postgresql import BYTEA
import datetime

Base = declarative_base()

class Role(Base):
    __tablename__ = 'roles'
    id = Column(Integer, primary_key=True)
    name = Column(String(80), unique=True, nullable=False)
    description = Column(String(255))

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password = Column(String(255), nullable=False)  # SCrypt hash
    mfa_secret_enc = Column(BYTEA, nullable=True)  # Encrypted MFA secret
    mfa_enabled = Column(Boolean, default=False)
    recovery_codes_enc = Column(BYTEA, nullable=True)
    active = Column(Boolean, default=True)
    last_active = Column(DateTime, default=datetime.datetime.utcnow)
    roles = relationship('Role', secondary='users_roles', backref=backref('users', lazy='dynamic'))

class UserRole(Base):
    __tablename__ = 'users_roles'
    user_id = Column(Integer, ForeignKey('users.id'), primary_key=True)
    role_id = Column(Integer, ForeignKey('roles.id'), primary_key=True)

class APIToken(Base):
    __tablename__ = 'api_tokens'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    token = Column(String(128), unique=True, nullable=False)
    scopes = Column(String(255))
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    user = relationship('User', backref=backref('api_tokens', lazy='dynamic'))

class JWTRevocation(Base):
    __tablename__ = 'jwt_revocation'
    id = Column(Integer, primary_key=True)
    jti = Column(String(36), unique=True, nullable=False, index=True)
    revoked_at = Column(DateTime, default=datetime.datetime.utcnow)

Index('ix_jwt_revocation_jti', JWTRevocation.jti) 