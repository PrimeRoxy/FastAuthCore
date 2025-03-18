import os
import logging
import random
import string
from datetime import datetime, timedelta
from dotenv import load_dotenv
load_dotenv()
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import EmailStr
from models import User
from database import get_db
from sqlalchemy.orm import Session

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment variables
ACCESS_TOKEN_EXPIRE_MINUTES = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")
REFRESH_TOKEN_EXPIRE_DAYS = 2
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")

# OAuth2 scheme and password context
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Helper functions for generating OTP, tokens, and verifying passwords 
def generate_otp() -> str:
    return "".join(random.choices(string.digits, k=6))


def generate_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now() + expires_delta
    else:
        expire = datetime.now() + timedelta(minutes=int(ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def generate_refresh_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now() + expires_delta
    else:
        expire = datetime.now() + timedelta(days=int(REFRESH_TOKEN_EXPIRE_DAYS))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


async def authenticate_user(email: EmailStr, password: str, db):
    user = db.query(User).filter(User.email == email).first()
    if user and verify_password(password, user.hashed_password):
        return user
    return False


async def get_user(username: str, db):
    return db.query(User).filter(User.username == username).first()


async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid user",
        headers={"WWW-Authenticate": "Bearer"}
    )

    try:
        # Decode JWT and extract fields from the payload
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("user_id")
        email = payload.get("email")
        phone_number = payload.get("phone_number")
        role_ids = payload.get("role_ids")  # List of role IDs from the token
        expiry_time = payload.get("exp")

        # Convert expiry_time to a datetime object and check if it's expired
        if isinstance(expiry_time, int):
            expiry_time = datetime.fromtimestamp(expiry_time)
            if expiry_time < datetime.now():
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Session timeout!",
                    headers={"WWW-Authenticate": "Bearer"}
                )

        # Ensure necessary fields exist
        if not phone_number or not role_ids or not user_id:
            raise credentials_exception

    except JWTError:
        raise credentials_exception

    # Fetch the user by user ID
    user = db.query(User).filter(User.uuid == user_id).first()

    # If user not found, raise an exception
    if not user:
        raise credentials_exception

    # Fetch the user's roles (assuming a many-to-many relationship with roles)
    user_roles = [role.id for role in user.roles]

    # Ensure at least one of the user's roles matches one of the roles in the token
    if not any(role_id in user_roles for role_id in role_ids):
        raise credentials_exception

    # Return the authenticated user
    return user
