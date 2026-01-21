import hashlib
from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException

from risk_engine.db.cookie_model import DeviceToken
from risk_engine.component.device_cookie import generate_device_token
from risk_engine.config import TOKEN_TTL_DAYS, EXPIRES_WITHIN_DAYS



# helper code
def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def insert_active_token(
    db,
    user="u1",
    device="d1",
    expires_in_days=30,
    token_hash="h_old",
):
    now = datetime.utcnow()
    row = DeviceToken(
        token_hash=token_hash,
        bound_user_id=user,
        bound_device_id=device,
        issued_at_utc=now,
        expires_at_utc=now + timedelta(days=expires_in_days),
        revoked=0,
    )
    db.add(row)
    db.commit()


    return row


def fetch_tokens(db, user, device):
    return (
        db.query(DeviceToken)
        .filter(
            DeviceToken.bound_user_id == user,
            DeviceToken.bound_device_id == device,
        )
        .order_by(DeviceToken.issued_at_utc.asc())
        .all()
    )


# ------------------------
# Test cases
# ------------------------

'''
Case 1: 
No active token exists for (user_id, device_id)
Verifies that when no active token exists for a user–device pair, 
the system issues a new token, stores only its hash in the database, marks it active,
 and returns the raw token and expiry to the caller.

'''


def test_case_1_first_issue(db_session):
    result = generate_device_token(
        db_session,
        user="u1",
        device="d1",
        force_rotate=False,
    )

    assert result["case"] == "first_issue"
    assert result["rotate"] is True
    assert result["raw_token"] is not None
    assert result["expires_at_utc"] is not None

    rows = fetch_tokens(db_session, "u1", "d1")
    assert len(rows) == 1
    assert rows[0].revoked == 0
    assert rows[0].token_hash == sha256_hex(result["raw_token"])


'''
Case 2: 
Verifies that when a valid, non-expiring token already exists and no forced rotation is requested,
the system performs no database write, returns no raw token,
and simply reports the existing token’s expiry.

'''


def test_case_2_no_rotate(db_session):
    active = insert_active_token(
        db_session,
        user="u1",
        device="d1",
        expires_in_days=30,
        token_hash="h_active",
    )

    result = generate_device_token(
        db_session,
        user="u1",
        device="d1",
        force_rotate=False,
    )

    assert result["case"] == "no_rotate"
    assert result["rotate"] is False
    assert result["raw_token"] is None
    assert result["expires_at_utc"] == active.expires_at_utc.isoformat()

    rows = fetch_tokens(db_session, "u1", "d1")
    assert len(rows) == 1
    assert rows[0].revoked == 0



'''
Case 3:
Periodic rotation (near expiry)

Verifies that when an active token exists but is close to expiry (within EXPIRES_WITHIN_DAYS),
the system revokes the old token, inserts a new active token row, and returns the new raw token
and new expiry.
'''
def test_case_3_periodic_rotate(db_session):
    # Arrange: create an active token that is near expiry
    # Trigger condition: (expires_at - now) <= EXPIRES_WITHIN_DAYS
    near_exp_days = max(EXPIRES_WITHIN_DAYS - 1, 0)

    insert_active_token(
        db_session,
        user="u1",
        device="d1",
        expires_in_days=near_exp_days,
        token_hash="h_old",
    )

    # Act
    result = generate_device_token(
        db_session,
        user="u1",
        device="d1",
        force_rotate=False,
    )

    # Assert: response
    assert result["case"] == "periodic_rotate"
    assert result["rotate"] is True
    assert result["raw_token"] is not None
    assert result["expires_at_utc"] is not None

    # Assert: DB state
    rows = fetch_tokens(db_session, "u1", "d1")
    assert len(rows) == 2

    old_row, new_row = rows[0], rows[1]
    assert old_row.revoked == 1
    assert new_row.revoked == 0

    # New token hash matches returned raw token
    assert new_row.token_hash == sha256_hex(result["raw_token"])

    # Expiry sanity check: returned expiry should be in the future
    exp = datetime.fromisoformat(result["expires_at_utc"])
    assert exp > datetime.utcnow()


'''
Case 4:
Risk-triggered rotation (force_rotate=True)

Verifies that when an active token exists, setting force_rotate=True forces rotation
even if the token is not near expiry. The old token is revoked, a new active token
row is inserted, and a new raw token + expiry are returned.
'''


def test_case_4_risk_rotate(db_session):
    insert_active_token(
        db_session,
        user="u1",
        device="d1",
        expires_in_days=999,
        token_hash="h_old",
    )

    result = generate_device_token(
        db_session,
        user="u1",
        device="d1",
        force_rotate=True,
    )

    assert result["case"] == "risk_rotate"
    assert result["rotate"] is True
    assert result["raw_token"] is not None

    rows = fetch_tokens(db_session, "u1", "d1")
    assert len(rows) == 2
    assert rows[0].revoked == 1
    assert rows[1].revoked == 0





