import logging
import uuid

import pytest
from fastapi.testclient import TestClient

from app.core.security import (
    BCRYPT_MAX_PASSWORD_BYTES,
    PasswordTooLongError,
    hash_password,
    verify_password,
)
from app.main import app

client = TestClient(app)

# 3 + 69 = 72 ASCII bytes (the maximum), and one byte more.
PW_72 = "Aa1" + "x" * 69
PW_73 = PW_72 + "y"

def _creds(password: str):
    username = f"pw_{uuid.uuid4().hex[:10]}"
    return {
        "username": username,
        "full_name": "Password Boundary",
        "email": f"{username}@example.com",
        "password": password,
    }

def _register(password: str):
    payload = _creds(password)
    return payload, client.post("/auth/register", json=payload)

# ---------------------------------------------------------------- unit level

def test_limit_constant_is_bcrypts_72_bytes():
    assert BCRYPT_MAX_PASSWORD_BYTES == 72

def test_hash_and_verify_normal_password():
    hashed = hash_password("Test@12345")
    assert hashed != "Test@12345"
    assert verify_password("Test@12345", hashed) is True
    assert verify_password("Test@12346", hashed) is False

def test_72_byte_password_is_accepted():
    assert len(PW_72.encode()) == 72
    assert verify_password(PW_72, hash_password(PW_72)) is True

def test_73_byte_password_is_rejected_not_truncated():
    assert len(PW_73.encode()) == 73
    with pytest.raises(PasswordTooLongError):
        hash_password(PW_73)

def test_verify_never_matches_a_password_differing_only_after_byte_72():
    hashed = hash_password(PW_72)
    # Without the guard, bcrypt would ignore the extra byte and say True.
    assert verify_password(PW_73, hashed) is False

@pytest.mark.parametrize(
    "password, ok",
    [
        ("é" * 36, True),    # 2 bytes each -> 72 bytes
        ("é" * 37, False),   # 74 bytes
        ("€" * 24, True),    # 3 bytes each -> 72 bytes
        ("€" * 25, False),   # 75 bytes
        ("🔒" * 18, True),   # 4 bytes each -> 72 bytes
        ("🔒" * 19, False),  # 76 bytes
    ],
)
def test_limit_counts_utf8_bytes_not_characters(password, ok):
    if ok:
        assert verify_password(password, hash_password(password)) is True
    else:
        with pytest.raises(PasswordTooLongError):
            hash_password(password)

def test_empty_and_invalid_passwords_are_handled_without_exceptions():
    with pytest.raises(ValueError):
        hash_password("")
    with pytest.raises(ValueError):
        hash_password("abc\x00defghi")
    hashed = hash_password("Test@12345")
    assert verify_password("", hashed) is False
    assert verify_password("Test@12345", "") is False
    assert verify_password("Test@12345", "not-a-bcrypt-hash") is False
    assert verify_password("\ud800" * 10, hashed) is False  # unencodable

# ------------------------------------------------------------------ register

def test_register_normal_password():
    _, response = _register("Test@12345")
    assert response.status_code in {200, 201}

def test_register_exactly_72_bytes_then_login_works():
    payload, response = _register(PW_72)
    assert response.status_code in {200, 201}, response.text
    login = client.post(
        "/auth/login",
        json={"email": payload["email"], "password": PW_72},
    )
    assert login.status_code == 200

def test_register_73_bytes_is_422():
    _, response = _register(PW_73)
    assert response.status_code == 422

def test_register_multibyte_over_limit_is_422_even_though_char_count_is_low():
    password = "é" * 37  # 37 characters but 74 bytes
    assert len(password) < 72 and len(password.encode()) > 72
    _, response = _register(password)
    assert response.status_code == 422

def test_register_multibyte_at_limit_is_accepted():
    _, response = _register("€" * 24)  # exactly 72 bytes
    assert response.status_code in {200, 201}

@pytest.mark.parametrize("password", ["", "short7!", "a" * 7])
def test_register_empty_or_too_short_is_422(password):
    _, response = _register(password)
    assert response.status_code == 422

def test_register_missing_password_is_422():
    payload = _creds("Test@12345")
    del payload["password"]
    assert client.post("/auth/register", json=payload).status_code == 422

def test_register_nul_byte_is_422_not_500():
    _, response = _register("Test@123\x0045")
    assert response.status_code == 422

# --------------------------------------------------------------------- login

def test_login_wrong_password_is_generic_401():
    payload, _ = _register("Test@12345")
    wrong = client.post(
        "/auth/login",
        json={"email": payload["email"], "password": "Wrong@12345"},
    )
    unknown = client.post(
        "/auth/login",
        json={"email": f"nobody_{uuid.uuid4().hex[:8]}@example.com", "password": "Wrong@12345"},
    )
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()  # no account-existence oracle

def test_login_short_wrong_password_is_401_not_422():
    payload, _ = _register("Test@12345")
    response = client.post(
        "/auth/login",
        json={"email": payload["email"], "password": "x"},
    )
    assert response.status_code == 401

def test_login_empty_password_is_422():
    payload, _ = _register("Test@12345")
    response = client.post(
        "/auth/login",
        json={"email": payload["email"], "password": ""},
    )
    assert response.status_code == 422

@pytest.mark.parametrize("password", [PW_73, "é" * 37])
def test_login_over_72_bytes_is_rejected_with_422(password):
    payload, _ = _register("Test@12345")
    response = client.post(
        "/auth/login",
        json={"email": payload["email"], "password": password},
    )
    assert response.status_code == 422

def test_login_72_byte_prefix_of_a_longer_password_cannot_log_in():
    # Registered with the 72-byte password; the 73-byte variant must not work.
    payload, _ = _register(PW_72)
    response = client.post(
        "/auth/login",
        json={"email": payload["email"], "password": PW_73},
    )
    assert response.status_code == 422

# --------------------------------------------- validation errors never leak

def test_422_body_and_logs_never_contain_the_submitted_password(caplog):
    secret = "LeakCheck!" + "q" * 70  # 80 chars -> invalid

    with caplog.at_level(logging.DEBUG):
        register = client.post("/auth/register", json=_creds(secret))
        login = client.post(
            "/auth/login",
            json={"email": "someone@example.com", "password": secret},
        )

    for response in (register, login):
        assert response.status_code == 422
        assert secret not in response.text
        assert "LeakCheck" not in response.text
        body = response.json()
        assert body["message"] == "ValidationError"
        for error in body["errors"]:
            assert set(error) <= {"type", "loc", "msg"}  # no input / ctx

    assert "LeakCheck" not in caplog.text
