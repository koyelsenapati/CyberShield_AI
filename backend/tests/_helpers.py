import uuid

from app.database.database import SessionLocal
from app.models.user import User

DEFAULT_PASSWORD = "Test@12345"

def register_and_login(client, password: str = DEFAULT_PASSWORD, prefix: str = "user"):
    """Register a fresh user through the real API and log in."""
    username = f"{prefix}_{uuid.uuid4().hex[:10]}"
    email = f"{username}@example.com"

    registered = client.post(
        "/auth/register",
        json={
            "username": username,
            "full_name": "Access Control Tester",
            "email": email,
            "password": password,
        },
    )
    assert registered.status_code in {200, 201}, registered.text

    login = client.post(
        "/auth/login",
        json={"email": email, "password": password},
    )
    assert login.status_code == 200, login.text

    return {
        "id": registered.json()["user_id"],
        "email": email,
        "password": password,
        "headers": {"Authorization": f"Bearer {login.json()['access_token']}"},
    }

def promote_to_admin(user_id: int) -> None:
    """
    Make an existing user an admin directly in the test database.

    There is intentionally no API for this; roles are never accepted from
    request bodies. The role is re-read from the database on every request.
    """
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        assert user is not None
        user.role = "admin"
        db.commit()
    finally:
        db.close()
