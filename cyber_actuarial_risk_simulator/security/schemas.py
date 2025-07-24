from pydantic import BaseModel, EmailStr, validator, constr
from typing import List, Optional
from zxcvbn import zxcvbn

class UserRegisterSchema(BaseModel):
    email: EmailStr
    password: constr(min_length=8)
    role: Optional[str] = 'RiskAnalyst'

    @validator('password')
    def password_strength(cls, v):
        result = zxcvbn(v)
        if result['score'] < 3:
            raise ValueError('Password too weak (zxcvbn score < 3)')
        return v

class UserLoginSchema(BaseModel):
    email: EmailStr
    password: str

class MFAVerifySchema(BaseModel):
    code: str
    recovery_code: Optional[str]

class APITokenSchema(BaseModel):
    scopes: List[str]

class RBACSchema(BaseModel):
    roles: List[str] 