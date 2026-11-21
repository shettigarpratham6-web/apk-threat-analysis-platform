"""Application configuration and environment variables."""

import os

API_KEY = os.getenv("API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# --- Authentication / session settings ---------------------------------------
JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "480"))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
AUTH_PROTECT_API = os.getenv("AUTH_PROTECT_API", "true").lower() == "true"
DATABASE_URL = os.getenv("DATABASE_URL", "")
