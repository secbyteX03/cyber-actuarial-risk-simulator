from functools import wraps
from flask import request, jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt, get_jwt_identity
from .models import User, JWTRevocation
from sqlalchemy.orm import Session

def rbac_required(roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            jti = claims['jti']
            db: Session = kwargs.get('db_session')
            if db and db.query(JWTRevocation).filter_by(jti=jti).first():
                return jsonify({'msg': 'Token revoked'}), 403
            user_id = get_jwt_identity()
            user = db.query(User).get(user_id)
            user_roles = [r.name for r in user.roles]
            if not any(role in user_roles for role in roles):
                return jsonify({'msg': 'Insufficient role'}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator 