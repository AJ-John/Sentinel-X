import os
import base64
import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timezone, timedelta

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from database import database

users_collection = database["users"]
audit_collection = database["security_audit"]
security = HTTPBearer(auto_error=False)

LOGIN_WINDOW_SECONDS = 300
MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 600
_login_attempts = {}

def _login_key(username: str, client_ip: str) -> str:
    return f"{client_ip}:{username.strip().lower()}"

def check_login_allowed(username: str, client_ip: str):
    now = time.time()
    key = _login_key(username, client_ip)
    record = _login_attempts.get(key)

    if not record:
        return

    if now - record["first_attempt"] > LOGIN_WINDOW_SECONDS:
        _login_attempts.pop(key, None)
        return

    if record["locked_until"] > now:
        remaining = int(record["locked_until"] - now)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts. Try again in about {max(1, remaining // 60)} minute(s).",
        )

def record_login_failure(username: str, client_ip: str):
    now = time.time()
    key = _login_key(username, client_ip)
    record = _login_attempts.get(key)

    if not record or now - record["first_attempt"] > LOGIN_WINDOW_SECONDS:
        record = {
            "first_attempt": now,
            "failures": 0,
            "locked_until": 0,
        }

    record["failures"] += 1

    if record["failures"] >= MAX_FAILED_LOGINS:
        record["locked_until"] = now + LOCKOUT_SECONDS

    _login_attempts[key] = record

def record_login_success(username: str, client_ip: str):
    _login_attempts.pop(_login_key(username, client_ip), None)

def write_audit(
    action: str,
    username: str = "",
    role: str = "",
    details: str = "",
    client_ip: str = "",
):
    try:
        audit_collection.insert_one({
            "action": action,
            "username": username,
            "role": role,
            "details": details,
            "client_ip": client_ip,
            "created_at": datetime.now(timezone.utc),
        })
    except Exception:
        pass

JWT_SECRET = os.getenv("SENTINELX_JWT_SECRET", "change-this-sentinelx-secret")
JWT_EXPIRE_MINUTES = int(os.getenv("SENTINELX_JWT_EXPIRE_MINUTES", "480"))
if JWT_SECRET == "change-this-sentinelx-secret":
    print("WARNING: SENTINELX_JWT_SECRET is using the development default. Change it before deployment.")



class LoginRequest(BaseModel):
    username: str
    password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "analyst"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=64,
    )
    return f"scrypt${_b64(salt)}${_b64(derived)}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, salt_b64, digest_b64 = stored_hash.split("$", 2)
        if algorithm != "scrypt":
            return False
        salt = _unb64(salt_b64)
        expected = _unb64(digest_b64)
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=2**14,
            r=8,
            p=1,
            dklen=64,
        )
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def _make_token(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = _b64(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64(json.dumps(payload, separators=(",", ":")).encode())
    message = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(
        JWT_SECRET.encode("utf-8"),
        message,
        hashlib.sha256,
    ).digest()
    return f"{header_b64}.{payload_b64}.{_b64(signature)}"


def _decode_token(token: str) -> dict:
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        message = f"{header_b64}.{payload_b64}".encode()
        expected = hmac.new(
            JWT_SECRET.encode("utf-8"),
            message,
            hashlib.sha256,
        ).digest()

        if not hmac.compare_digest(expected, _unb64(signature_b64)):
            raise ValueError("Invalid signature")

        payload = json.loads(_unb64(payload_b64).decode("utf-8"))

        if int(payload.get("exp", 0)) < int(time.time()):
            raise ValueError("Token expired")

        return payload
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token",
        )


def authenticate_user(username: str, password: str):
    user = users_collection.find_one({"username": username})
    if not user or not verify_password(password, user.get("password_hash", "")):
        return None
    return user


def create_access_token(user: dict) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user["_id"]),
        "username": user["username"],
        "role": user.get("role", "analyst"),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_EXPIRE_MINUTES)).timestamp()),
    }
    return _make_token(payload)


def require_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
):
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    return _decode_token(credentials.credentials)


def require_admin(
    current_user=Depends(require_user),
):
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


def list_users():
    users = users_collection.find(
        {},
        {"password_hash": 0},
    )
    return [
        {
            "id": str(user["_id"]),
            "username": user.get("username"),
            "role": user.get("role", "analyst"),
            "created_at": user.get("created_at"),
        }
        for user in users
    ]


def create_user(username: str, password: str, role: str):
    username = username.strip()
    role = role.lower().strip()

    if not username:
        raise ValueError("Username is required")
    if len(password) < 8:
        raise ValueError("Password must contain at least 8 characters")
    if role not in {"admin", "analyst"}:
        raise ValueError("Role must be admin or analyst")
    if users_collection.find_one({"username": username}):
        raise ValueError("Username already exists")

    result = users_collection.insert_one({
        "username": username,
        "password_hash": hash_password(password),
        "role": role,
        "created_at": datetime.now(timezone.utc),
    })

    return {
        "id": str(result.inserted_id),
        "username": username,
        "role": role,
    }


def delete_user(username: str, current_username: str):
    username = username.strip()

    if username == current_username:
        raise ValueError("You cannot delete your own account")

    result = users_collection.delete_one({"username": username})
    return result.deleted_count > 0


def token_from_string(token: str) -> dict:
    return _decode_token(token)


def ensure_demo_admin():
    """Create a demo admin only when no SentinelX users exist."""
    if users_collection.count_documents({}) > 0:
        return

    username = os.getenv("SENTINELX_ADMIN_USERNAME", "admin")
    password = os.getenv("SENTINELX_ADMIN_PASSWORD", "SentinelX@123")

    users_collection.insert_one({
        "username": username,
        "password_hash": hash_password(password),
        "role": "admin",
        "created_at": datetime.now(timezone.utc),
    })


def public_user(user: dict) -> dict:
    return {
        "username": user.get("username"),
        "role": user.get("role", "analyst"),
    }
