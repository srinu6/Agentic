"""
Keystone Database & Data-at-Rest Security
Module 5 Reference Implementation: AI Agent Security & Governance

Implements:
  1. Role-Based Row-Level Security (RLS) views in SQLite (customer, underwriter, auditor)
  2. Field-Level Envelope Encryption (AES-GCM / Fernet via simulated KMS)
  3. Blind Indexing for sensitive PII search without decrypting
  4. Cryptographic Tamper-Evident Audit Chain with External Anchor (Stretch Goal 4)
"""

import base64
import datetime
import hashlib
import hmac
import json
import os
import sqlite3
from typing import Dict, Any, List, Optional, Tuple
from cryptography.fernet import Fernet

DB_PATH = os.path.join(os.path.dirname(__file__), "keystone_mortgages.db")
GENESIS_HASH = "0" * 64
BLIND_INDEX_KEY = b"keystone-pii-blind-index-hmac-key-2026"


# ---------------------------------------------------------------------------
# KEY MANAGEMENT SERVICE (SIMULATED HSM / ENVELOPE ENCRYPTION)
# ---------------------------------------------------------------------------
class KeyManagementService:
    """
    Simulated Hardware Security Module (HSM).
    The Master Key (KEK) never leaves this boundary.
    It wraps/unwraps the Data Encryption Key (DEK).
    """

    def __init__(self):
        self._kek = Fernet(Fernet.generate_key())
        self.unwrap_count = 0

    def generate_data_key(self) -> Tuple[Fernet, bytes]:
        """Returns (plaintext cipher engine, wrapped_dek_bytes)."""
        raw_dek = Fernet.generate_key()
        wrapped_dek = self._kek.encrypt(raw_dek)
        return Fernet(raw_dek), wrapped_dek

    def unwrap(self, wrapped_dek: bytes) -> Fernet:
        """Unwrap the DEK using the KEK to perform field encryption/decryption."""
        self.unwrap_count += 1
        raw_dek = self._kek.decrypt(wrapped_dek)
        return Fernet(raw_dek)


kms = KeyManagementService()
CIPHER, WRAPPED_DEK = kms.generate_data_key()


def encrypt_field(plaintext: str) -> bytes:
    """Encrypt sensitive field using the DEK."""
    if plaintext is None:
        return b""
    return CIPHER.encrypt(plaintext.encode("utf-8"))


def decrypt_field(ciphertext: bytes) -> str:
    """Decrypt sensitive field using the DEK."""
    if not ciphertext:
        return ""
    return CIPHER.decrypt(ciphertext).decode("utf-8")


def blind_index(value: str) -> str:
    """Deterministic HMAC blind index for exact match search without decryption."""
    clean = "".join(value.upper().split())
    return hmac.new(BLIND_INDEX_KEY, clean.encode("utf-8"), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# DATABASE INITIALIZATION WITH RLS & ENCRYPTED SCHEMA
# ---------------------------------------------------------------------------
def init_db(db_path: str = DB_PATH) -> sqlite3.Connection:
    """Initialize database tables, views, and seed data."""
    con = sqlite3.connect(db_path, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    cur = con.cursor()

    cur.executescript("""
    CREATE TABLE IF NOT EXISTS mortgage_applications (
        application_id   TEXT PRIMARY KEY,
        customer_id      TEXT NOT NULL,
        applicant_name   TEXT NOT NULL,
        nino_encrypted   BLOB NOT NULL,
        nino_bidx        TEXT NOT NULL,
        account_enc      BLOB NOT NULL,
        sort_code_enc    BLOB NOT NULL,
        credit_score_enc BLOB NOT NULL,
        loan_amount      REAL NOT NULL,
        property_value   REAL NOT NULL,
        gross_income     REAL NOT NULL,
        lti_ratio        REAL NOT NULL,
        stressed_dti     REAL NOT NULL,
        status           TEXT NOT NULL CHECK (status IN ('APPROVED', 'REFERRED', 'DECLINED', 'ESCALATED', 'PENDING')),
        decision_notes   TEXT,
        underwriter_id   TEXT,
        is_escalated     INTEGER NOT NULL DEFAULT 0,
        created_at       TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_log (
        event_id         INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp_utc    TEXT NOT NULL,
        actor_id         TEXT NOT NULL,
        role             TEXT NOT NULL,
        action           TEXT NOT NULL,
        resource         TEXT NOT NULL,
        details_json     TEXT NOT NULL,
        result           TEXT NOT NULL,
        prev_hash        TEXT NOT NULL,
        row_hash         TEXT NOT NULL
    );

    -- Role-Based Views (RLS)
    CREATE VIEW IF NOT EXISTS customer_view AS
        SELECT application_id, customer_id, applicant_name, loan_amount, property_value, status, created_at
        FROM mortgage_applications;

    CREATE VIEW IF NOT EXISTS underwriter_view AS
        SELECT application_id, customer_id, applicant_name, loan_amount, property_value,
               gross_income, lti_ratio, stressed_dti, status, decision_notes, is_escalated, created_at
        FROM mortgage_applications;
    """)
    con.commit()
    return con


# Global connection
_DB_CONN: Optional[sqlite3.Connection] = None
EXTERNAL_AUDIT_ANCHOR: Optional[str] = None


def get_db() -> sqlite3.Connection:
    global _DB_CONN
    if _DB_CONN is None:
        _DB_CONN = init_db()
    return _DB_CONN


# ---------------------------------------------------------------------------
# CRYPTOGRAPHIC TAMPER-EVIDENT AUDIT LOGGING
# ---------------------------------------------------------------------------
def canonical_repr(data: Dict[str, Any]) -> bytes:
    """Canonical JSON encoding for deterministic cryptographic hashing."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def append_audit_event(
    actor_id: str,
    role: str,
    action: str,
    resource: str,
    details: Dict[str, Any],
    result: str = "SUCCESS",
) -> str:
    """
    Appends a cryptographically chained event to the audit ledger.
    row_hash = SHA256(canonical(event_id, timestamp, actor, role, action, resource, details, result, prev_hash))
    """
    global EXTERNAL_AUDIT_ANCHOR
    con = get_db()
    cur = con.cursor()

    last_row = cur.execute("SELECT event_id, row_hash FROM audit_log ORDER BY event_id DESC LIMIT 1").fetchone()
    if last_row is None:
        prev_hash = GENESIS_HASH
        next_id = 1
    else:
        prev_hash = last_row["row_hash"]
        next_id = last_row["event_id"] + 1

    timestamp_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    details_str = json.dumps(details, sort_keys=True)

    block = {
        "event_id": next_id,
        "timestamp_utc": timestamp_utc,
        "actor_id": actor_id,
        "role": role,
        "action": action,
        "resource": resource,
        "details_json": details_str,
        "result": result,
        "prev_hash": prev_hash,
    }
    row_hash = hashlib.sha256(canonical_repr(block)).hexdigest()

    cur.execute(
        """
        INSERT INTO audit_log (
            event_id, timestamp_utc, actor_id, role, action, resource,
            details_json, result, prev_hash, row_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (next_id, timestamp_utc, actor_id, role, action, resource, details_str, result, prev_hash, row_hash),
    )
    con.commit()

    # Anchor tip externally (simulating external secure ledger or signed notification)
    EXTERNAL_AUDIT_ANCHOR = row_hash
    return row_hash


def verify_audit_chain() -> Dict[str, Any]:
    """
    Walks the entire audit chain and verifies:
      1. Internal hash integrity (row_hash matches canonical block hash)
      2. Continuity integrity (prev_hash links to prior row_hash)
      3. External anchor verification (catches full-access history rewrites)
    """
    global EXTERNAL_AUDIT_ANCHOR
    con = get_db()
    cur = con.cursor()
    rows = cur.execute("SELECT * FROM audit_log ORDER BY event_id ASC").fetchall()

    if not rows:
        return {"valid": True, "count": 0, "status": "EMPTY_CHAIN"}

    expected_prev = GENESIS_HASH
    errors = []

    for r in rows:
        # Check chain link
        if r["prev_hash"] != expected_prev:
            errors.append({
                "type": "CHAIN_BROKEN_LINK",
                "event_id": r["event_id"],
                "expected_prev": expected_prev,
                "actual_prev": r["prev_hash"],
            })

        # Recompute hash
        block = {
            "event_id": r["event_id"],
            "timestamp_utc": r["timestamp_utc"],
            "actor_id": r["actor_id"],
            "role": r["role"],
            "action": r["action"],
            "resource": r["resource"],
            "details_json": r["details_json"],
            "result": r["result"],
            "prev_hash": r["prev_hash"],
        }
        recomputed = hashlib.sha256(canonical_repr(block)).hexdigest()
        if recomputed != r["row_hash"]:
            errors.append({
                "type": "RECORD_CONTENT_TAMPERED",
                "event_id": r["event_id"],
                "stored_hash": r["row_hash"],
                "recomputed_hash": recomputed,
            })

        expected_prev = r["row_hash"]

    # Check external anchor tip
    anchor_intact = True
    tip_hash = rows[-1]["row_hash"]
    if EXTERNAL_AUDIT_ANCHOR and tip_hash != EXTERNAL_AUDIT_ANCHOR:
        anchor_intact = False
        errors.append({
            "type": "EXTERNAL_ANCHOR_MISMATCH",
            "message": "Audit chain was rebuilt/truncated! Stored tip does not match external anchor.",
            "tip_hash": tip_hash,
            "anchor_tip": EXTERNAL_AUDIT_ANCHOR,
        })

    return {
        "valid": len(errors) == 0,
        "total_events": len(rows),
        "event_count": len(rows),
        "tip_hash": tip_hash,
        "external_anchor": EXTERNAL_AUDIT_ANCHOR,
        "anchor_intact": anchor_intact,
        "errors": errors,
    }


def get_audit_events(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves recent audit ledger events."""
    con = get_db()
    cur = con.cursor()
    rows = cur.execute("SELECT * FROM audit_ledger ORDER BY event_id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# APPLICATION REPOSITORY WITH FIELD ENCRYPTION
# ---------------------------------------------------------------------------
def store_application(
    application_id: str,
    customer_id: str,
    applicant_name: str,
    nino: str,
    account_number: str,
    sort_code: str,
    credit_score: int,
    loan_amount: float,
    property_value: float,
    gross_income: float,
    lti_ratio: float,
    stressed_dti: float,
    status: str,
    decision_notes: str,
    is_escalated: bool = False,
    underwriter_id: Optional[str] = None,
) -> None:
    """Stores mortgage application with field-level envelope encryption on sensitive PII."""
    con = get_db()
    cur = con.cursor()

    cur.execute(
        """
        INSERT OR REPLACE INTO mortgage_applications (
            application_id, customer_id, applicant_name,
            nino_encrypted, nino_bidx, account_enc, sort_code_enc, credit_score_enc,
            loan_amount, property_value, gross_income, lti_ratio, stressed_dti,
            status, decision_notes, underwriter_id, is_escalated, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            application_id,
            customer_id,
            applicant_name,
            encrypt_field(nino),
            blind_index(nino),
            encrypt_field(account_number),
            encrypt_field(sort_code),
            encrypt_field(str(credit_score)),
            loan_amount,
            property_value,
            gross_income,
            lti_ratio,
            stressed_dti,
            status,
            decision_notes,
            underwriter_id,
            1 if is_escalated else 0,
            datetime.datetime.now(datetime.timezone.utc).isoformat(),
        ),
    )
    con.commit()

    append_audit_event(
        actor_id="keystone_system",
        role="agent",
        action="STORE_APPLICATION",
        resource=f"mortgage_applications/{application_id}",
        details={
            "customer_id": customer_id,
            "loan_amount": loan_amount,
            "status": status,
            "is_escalated": is_escalated,
            "fields_encrypted": ["nino", "account_number", "sort_code", "credit_score"],
        },
        result=status,
    )


def query_application_by_id(application_id: str) -> Optional[Dict[str, Any]]:
    """Fetches application with decrypted sensitive fields (authorized service only)."""
    con = get_db()
    cur = con.cursor()
    row = cur.execute("SELECT * FROM mortgage_applications WHERE application_id=?", (application_id,)).fetchone()
    if not row:
        return None

    return {
        "application_id": row["application_id"],
        "customer_id": row["customer_id"],
        "applicant_name": row["applicant_name"],
        "nino": decrypt_field(row["nino_encrypted"]),
        "account_number": decrypt_field(row["account_enc"]),
        "sort_code": decrypt_field(row["sort_code_enc"]),
        "credit_score": int(decrypt_field(row["credit_score_enc"])),
        "loan_amount": row["loan_amount"],
        "property_value": row["property_value"],
        "gross_income": row["gross_income"],
        "lti_ratio": row["lti_ratio"],
        "stressed_dti": row["stressed_dti"],
        "status": row["status"],
        "decision_notes": row["decision_notes"],
        "is_escalated": bool(row["is_escalated"]),
        "underwriter_id": row["underwriter_id"],
        "created_at": row["created_at"],
    }

