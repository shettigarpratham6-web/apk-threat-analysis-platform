"""Authentication routes: signup, login, logout and current-user lookup.

Sessions are a signed JWT stored in an httpOnly, SameSite=Lax cookie so that
<iframe>/<img>/<a download> requests to the report and device-screen endpoints
are authenticated too (a Bearer header cannot be attached to those).
"""

import re
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from loguru import logger
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend import config
from backend.database import crud
from backend.database.database import get_db
from backend.database.models import User

router = APIRouter()

COOKIE_NAME = "apk_session"
_ALGORITHM = "HS256"

_JWT_SECRET = config.JWT_SECRET or secrets.token_urlsafe(48)
if not config.JWT_SECRET:
    logger.warning("JWT_SECRET is not set: using a random per-process secret. Sessions reset on every restart.")

# Used to burn the same CPU time when the email is unknown (blunts user-enumeration by timing).
_DUMMY_HASH = bcrypt.hashpw(b"not-a-real-password", bcrypt.gensalt())

# --- Brute-force protection (in-memory; per client IP + email) ---------------
_MAX_FAILURES = 5
_WINDOW_SECONDS = 15 * 60
_failures: dict[str, deque] = defaultdict(deque)
_failures_lock = threading.Lock()


def _attempt_key(request: Request, email: str) -> str:
    host = request.client.host if request.client else "unknown"
    return f"{host}|{email}"


def _assert_not_locked(key: str) -> None:
    now = time.monotonic()
    with _failures_lock:
        attempts = _failures[key]
        while attempts and now - attempts[0] > _WINDOW_SECONDS:
            attempts.popleft()
        if len(attempts) >= _MAX_FAILURES:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed attempts. Try again in 15 minutes.",
            )


def _record_failure(key: str) -> None:
    with _failures_lock:
        _failures[key].append(time.monotonic())


def _clear_failures(key: str) -> None:
    with _failures_lock:
        _failures.pop(key, None)


# --- Schemas -------------------------------------------------------------------
class SignupIn(BaseModel):
    full_name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)

    @field_validator("full_name")
    @classmethod
    def _clean_name(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 2:
            raise ValueError("Full name must be at least 2 characters.")
        return value

    @field_validator("password")
    @classmethod
    def _strong_enough(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 72:  # bcrypt silently/loudly rejects > 72 bytes
            raise ValueError("Password must be at most 72 bytes.")
        if not re.search(r"[A-Za-z]", value) or not re.search(r"\d", value):
            raise ValueError("Password must contain at least one letter and one number.")
        return value


class LoginIn(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=72)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    full_name: str
    created_at: datetime


# --- Helpers -------------------------------------------------------------------
def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def _verify_password(password: str, password_hash: bytes | str) -> bool:
    if isinstance(password_hash, str):
        password_hash = password_hash.encode("utf-8")
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash)
    except ValueError:
        return False


def _issue_session(response: Response, user: User) -> None:
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=config.JWT_EXPIRE_MINUTES)
    token = jwt.encode({"sub": str(user.id), "iat": now, "exp": expires}, _JWT_SECRET, algorithm=_ALGORITHM)
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=config.JWT_EXPIRE_MINUTES * 60,
        httponly=True,
        secure=config.COOKIE_SECURE,
        samesite="lax",
        path="/",
    )


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Dependency: resolve the logged-in user from the session cookie (or a Bearer token)."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        header = request.headers.get("authorization", "")
        if header.lower().startswith("bearer "):
            token = header[7:].strip()

    unauthorized = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")
    if not token:
        raise unauthorized
    try:
        payload = jwt.decode(token, _JWT_SECRET, algorithms=[_ALGORITHM])
        user = crud.get_user(db, int(payload["sub"]))
    except (jwt.PyJWTError, KeyError, ValueError):
        raise unauthorized
    if user is None:
        raise unauthorized
    return user


# --- Routes --------------------------------------------------------------------
@router.post("/signup", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def signup(payload: SignupIn, response: Response, db: Session = Depends(get_db)):
    email = str(payload.email).strip().lower()
    if crud.get_user_by_email(db, email):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An account with this email already exists.")
    try:
        user = crud.create_user(
            db, email=email, full_name=payload.full_name, password_hash=_hash_password(payload.password)
        )
    except IntegrityError:  # lost a race with a concurrent signup
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An account with this email already exists.")
    _issue_session(response, user)
    return user


@router.post("/login", response_model=UserOut)
def login(payload: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    key = _attempt_key(request, email)
    _assert_not_locked(key)

    user = crud.get_user_by_email(db, email)
    password_ok = _verify_password(payload.password, user.password_hash if user else _DUMMY_HASH)
    if not user or not password_ok:
        _record_failure(key)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")

    _clear_failures(key)
    crud.touch_last_login(db, user)
    _issue_session(response, user)
    return user


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(key=COOKIE_NAME, path="/", samesite="lax", secure=config.COOKIE_SECURE, httponly=True)
    return {"status": "ok"}


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user
