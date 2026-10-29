from __future__ import annotations

from datetime import timedelta

import pytest

from tests.conftest import ADMIN_PW, ANALYST_PW
from threatlens.errors import (
    AuthenticationError,
    AuthorizationError,
    RateLimitedError,
    SessionExpiredError,
    SetupError,
    ValidationFailedError,
)
from threatlens.models.domain import Role
from threatlens.repositories import audit_repo
from threatlens.security.passwords import hash_password, verify_password
from threatlens.security.rbac import ROLE_PERMISSIONS, Permission
from threatlens.timeutil import to_iso, utcnow

# --- first-run setup --------------------------------------------------------------------


def test_setup_required_on_empty_db(services):
    assert services.auth.setup_required()


def test_setup_requires_valid_code(services):
    services.auth.issue_setup_code()
    with pytest.raises(SetupError):
        services.auth.create_initial_admin(setup_code="wrong", username="admin", password=ADMIN_PW)
    assert services.auth.setup_required()
    with services.db.connect() as conn:
        outcomes = [r["outcome"] for r in audit_repo.list_events(conn, action="setup.create_admin")]
    assert outcomes == ["denied"]


def test_setup_without_issued_code_fails(services):
    with pytest.raises(SetupError):
        services.auth.create_initial_admin(
            setup_code="anything", username="admin", password=ADMIN_PW
        )


def test_expired_setup_code_rejected(services):
    code = services.auth.issue_setup_code()
    with services.db.transaction() as conn:
        value = conn.execute("SELECT value FROM app_config WHERE key='setup_code'").fetchone()[0]
        past = to_iso(utcnow() - timedelta(minutes=1))
        conn.execute(
            "UPDATE app_config SET value=? WHERE key='setup_code'",
            (value.split("|")[0] + "|" + past,),
        )
    with pytest.raises(SetupError):
        services.auth.create_initial_admin(setup_code=code, username="admin", password=ADMIN_PW)


def test_setup_closed_after_first_admin(services, admin_token):
    assert not services.auth.setup_required()
    with pytest.raises(SetupError):
        services.auth.issue_setup_code()
    with pytest.raises(SetupError):
        services.auth.create_initial_admin(setup_code="x", username="evil", password=ADMIN_PW)


def test_setup_code_is_single_use(services):
    code = services.auth.issue_setup_code()
    services.auth.create_initial_admin(setup_code=code, username="admin", password=ADMIN_PW)
    with pytest.raises(SetupError):
        services.auth.create_initial_admin(setup_code=code, username="admin2", password=ADMIN_PW)


@pytest.mark.parametrize("pw", ["short", "admin-Strong-Pass-1", "aaaaaaaaaaaaaaaa", "password1234"])
def test_weak_passwords_rejected(services, pw):
    code = services.auth.issue_setup_code()
    with pytest.raises(ValidationFailedError):
        services.auth.create_initial_admin(setup_code=code, username="admin", password=pw)


@pytest.mark.parametrize("name", ["ab", "bad name", "x" * 65, "<script>", "admin;--"])
def test_invalid_usernames_rejected(services, name):
    code = services.auth.issue_setup_code()
    with pytest.raises(ValidationFailedError):
        services.auth.create_initial_admin(setup_code=code, username=name, password=ADMIN_PW)


# --- passwords / login ------------------------------------------------------------------


def test_password_hash_is_argon2id_and_not_plaintext(services, admin_token):
    with services.db.connect() as conn:
        stored = conn.execute("SELECT password_hash FROM users").fetchone()[0]
    assert stored.startswith("$argon2id$")
    assert ADMIN_PW not in stored
    assert verify_password(stored, ADMIN_PW)
    assert not verify_password(stored, ADMIN_PW + "x")
    assert not verify_password("garbage-hash", ADMIN_PW)


def test_password_never_in_audit_log(services, admin_token):
    with pytest.raises(AuthenticationError):
        services.auth.login("admin", "Wrong-Password-123")
    with services.db.connect() as conn:
        blob = " ".join(str(dict(r)) for r in audit_repo.list_events(conn))
    assert ADMIN_PW not in blob and "Wrong-Password-123" not in blob


def test_wrong_password_and_unknown_user_same_error(services, admin_token):
    with pytest.raises(AuthenticationError) as a:
        services.auth.login("admin", "Wrong-Password-123")
    with pytest.raises(AuthenticationError) as b:
        services.auth.login("nobody", "Wrong-Password-123")
    assert a.value.public_message == b.value.public_message


def test_login_throttled_after_max_failures(services, admin_token):
    for _ in range(services.settings.login_max_failures):
        with pytest.raises(AuthenticationError):
            services.auth.login("admin", "Wrong-Password-123")
    # Even the correct password is refused during lockout.
    with pytest.raises(RateLimitedError):
        services.auth.login("admin", ADMIN_PW)


def test_unknown_user_throttled_identically(services, admin_token):
    for _ in range(services.settings.login_max_failures):
        with pytest.raises(AuthenticationError):
            services.auth.login("ghost", "Wrong-Password-123")
    with pytest.raises(RateLimitedError):
        services.auth.login("ghost", "Wrong-Password-123")


def test_global_throttle(services, admin_token):
    services.settings.global_login_failures_per_minute = 3
    for i in range(3):
        with pytest.raises(AuthenticationError):
            services.auth.login(f"user{i}", "Wrong-Password-123")
    with pytest.raises(RateLimitedError):
        services.auth.login("admin", ADMIN_PW)


def test_disabled_user_cannot_login(services, admin_token, analyst_token):
    uid = next(u.id for u in services.users.list_users(admin_token) if u.username == "analyst1")
    services.users.set_active(admin_token, uid, False)
    with pytest.raises(SessionExpiredError):
        services.auth.resolve(analyst_token)
    with pytest.raises(AuthenticationError):
        services.auth.login("analyst1", ANALYST_PW)


def test_legacy_hash_is_upgraded_on_login(services, admin_token):
    from argon2 import PasswordHasher

    weak = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(ADMIN_PW)
    with services.db.transaction() as conn:
        conn.execute("UPDATE users SET password_hash=? WHERE username='admin'", (weak,))
    services.auth.login("admin", ADMIN_PW)
    with services.db.connect() as conn:
        assert conn.execute("SELECT password_hash FROM users").fetchone()[0] != weak


def test_hash_password_unique_salts():
    assert hash_password("Same-Password-123") != hash_password("Same-Password-123")


# --- sessions ---------------------------------------------------------------------------


def test_session_token_not_stored_in_plaintext(services, admin_token):
    with services.db.connect() as conn:
        hashes = [r[0] for r in conn.execute("SELECT token_hash FROM sessions")]
    assert admin_token not in hashes and len(hashes[0]) == 64


@pytest.mark.parametrize("token", [None, "", "forged-token", "x" * 500])
def test_invalid_tokens_rejected(services, admin_token, token):
    with pytest.raises(SessionExpiredError):
        services.auth.resolve(token)


def test_logout_revokes_session(services, admin_token):
    services.auth.logout(admin_token)
    with pytest.raises(SessionExpiredError):
        services.auth.resolve(admin_token)


def test_absolute_expiry(services, admin_token):
    with services.db.transaction() as conn:
        conn.execute("UPDATE sessions SET expires_at=?", (to_iso(utcnow() - timedelta(seconds=1)),))
    with pytest.raises(SessionExpiredError):
        services.auth.resolve(admin_token)


def test_idle_expiry(services, admin_token):
    idle = services.settings.session_idle_minutes + 1
    with services.db.transaction() as conn:
        conn.execute(
            "UPDATE sessions SET last_seen_at=?", (to_iso(utcnow() - timedelta(minutes=idle)),)
        )
    with pytest.raises(SessionExpiredError):
        services.auth.resolve(admin_token)


def test_password_change_revokes_sessions(services, admin_token):
    with pytest.raises(AuthenticationError):
        services.auth.change_own_password(admin_token, "not-current-pass", "New-Strong-Password-55")
    services.auth.change_own_password(admin_token, ADMIN_PW, "New-Strong-Password-55")
    with pytest.raises(SessionExpiredError):
        services.auth.resolve(admin_token)
    services.auth.login("admin", "New-Strong-Password-55")


# --- authorization / escalation ---------------------------------------------------------


def test_role_permission_matrix_is_monotonic():
    assert ROLE_PERMISSIONS[Role.VIEWER] < ROLE_PERMISSIONS[Role.ANALYST]
    assert ROLE_PERMISSIONS[Role.ANALYST] < ROLE_PERMISSIONS[Role.ADMIN]
    assert Permission.MANAGE_USERS not in ROLE_PERMISSIONS[Role.ANALYST]
    assert Permission.DECIDE_RESPONSE not in ROLE_PERMISSIONS[Role.VIEWER]


def test_viewer_cannot_manage_users(services, viewer_token):
    with pytest.raises(AuthorizationError):
        services.users.create_user(viewer_token, username="x1x", password=ADMIN_PW, role=Role.ADMIN)
    with pytest.raises(AuthorizationError):
        services.users.list_users(viewer_token)


def test_analyst_cannot_create_admin_or_self_promote(services, analyst_token):
    with pytest.raises(AuthorizationError):
        services.users.create_user(
            analyst_token, username="evil", password=ADMIN_PW, role=Role.ADMIN
        )
    me = services.auth.resolve(analyst_token)
    with pytest.raises(AuthorizationError):
        services.users.change_role(analyst_token, me.user_id, Role.ADMIN)
    assert services.auth.resolve(analyst_token).role == Role.ANALYST


def test_admin_cannot_change_own_role(services, admin_token):
    me = services.auth.resolve(admin_token)
    with pytest.raises(AuthorizationError):
        services.users.change_role(admin_token, me.user_id, Role.VIEWER)
    with services.db.connect() as conn:
        rows = audit_repo.list_events(conn, action="user.change_role")
    assert rows[0]["outcome"] == "denied"
    assert services.auth.resolve(admin_token).role == Role.ADMIN


def test_admin_cannot_disable_self_but_can_disable_other_admin(services, admin_token):
    services.users.create_user(
        admin_token, username="admin2", password=ADMIN_PW + "x", role=Role.ADMIN
    )
    token2 = services.auth.login("admin2", ADMIN_PW + "x")
    with pytest.raises(AuthorizationError):
        services.users.set_active(token2, services.auth.resolve(token2).user_id, False)
    services.users.set_active(token2, services.auth.resolve(admin_token).user_id, False)
    with pytest.raises(SessionExpiredError):
        services.auth.resolve(admin_token)


def test_duplicate_username_rejected_generically(services, admin_token):
    with pytest.raises(ValidationFailedError) as exc:
        services.users.create_user(
            admin_token, username="ADMIN", password=ADMIN_PW + "y", role=Role.VIEWER
        )
    assert "UNIQUE" not in exc.value.public_message


def test_role_change_takes_effect_immediately(services, admin_token, analyst_token):
    uid = services.auth.resolve(analyst_token).user_id
    services.auth.authorize(analyst_token, Permission.IMPORT_EVENTS)
    services.users.change_role(admin_token, uid, Role.VIEWER)
    with pytest.raises(SessionExpiredError):  # sessions revoked on role change
        services.auth.authorize(analyst_token, Permission.IMPORT_EVENTS)
    new_token = services.auth.login("analyst1", ANALYST_PW)
    with pytest.raises(AuthorizationError):
        services.auth.authorize(new_token, Permission.IMPORT_EVENTS)


def test_denied_authorization_is_audited(services, viewer_token):
    with pytest.raises(AuthorizationError):
        services.auth.authorize(viewer_token, Permission.MANAGE_USERS)
    with services.db.connect() as conn:
        rows = audit_repo.list_events(conn, action="authz.denied")
        assert rows and rows[0]["actor_username"] == "viewer1"
        assert audit_repo.verify_chain(conn).ok
