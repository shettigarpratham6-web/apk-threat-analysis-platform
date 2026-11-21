"""Test bootstrap: runs before any test module imports backend.main."""

import os
import tempfile

# Existing endpoint tests call the API without logging in, so switch route protection off for them.
# tests/test_auth.py builds its own app that DOES enforce get_current_user.
os.environ["AUTH_PROTECT_API"] = "false"
os.environ.setdefault("JWT_SECRET", "test-secret-for-pytest-only-0123456789abcdef")
os.environ["DATABASE_URL"] = f"sqlite:///{tempfile.mkdtemp()}/test_auth.db"
