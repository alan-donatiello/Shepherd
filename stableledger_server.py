"""
Shepherd Backend Server
Wraps the on-chain scanner in an HTTP API the browser UI calls.

Usage:
    python stableledger_server.py

Then open http://localhost:8090 in your browser.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
import threading
import ssl
ssl._create_default_https_context = ssl._create_unverified_context
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path


# ======================== DATABASE (MULTI-TENANT PERSISTENCE) ========================
# Data model: an Organization is a Shepherd API customer (e.g. a platform embedding
# Shepherd). Each org has one or more API keys. Wallets belong to an org and, optionally,
# to one of the org's own end users (identified by an external_id the org provides —
# no need for them to sync internal UUIDs with us). Everything else (transactions,
# chart of accounts, rules, audit log) is scoped by org_id so tenants never see each other's data.

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
DB_AVAILABLE = False
DB_UNAVAILABLE_REASON = "DATABASE_URL is not set on this service"
db_pool = None

if DATABASE_URL:
    try:
        import psycopg2
        import psycopg2.extras
        from psycopg2 import pool as pg_pool
        _db_url = DATABASE_URL.replace("postgres://", "postgresql://", 1)
        db_pool = pg_pool.SimpleConnectionPool(1, 10, _db_url)
        DB_AVAILABLE = True
    except ImportError as e:
        DB_UNAVAILABLE_REASON = f"psycopg2 is not installed ({e}) — check that requirements.txt is present and was picked up by the build"
        print(f"  [DB] {DB_UNAVAILABLE_REASON}")
        DB_AVAILABLE = False
    except Exception as e:
        DB_UNAVAILABLE_REASON = f"could not connect: {e}"
        print(f"  [DB] {DB_UNAVAILABLE_REASON}")
        DB_AVAILABLE = False


def db_conn():
    if not DB_AVAILABLE:
        return None
    return db_pool.getconn()


def db_release(conn):
    if DB_AVAILABLE and conn:
        db_pool.putconn(conn)


def db_init_schema():
    if not DB_AVAILABLE:
        print(f"  [DB] Running in memory-only mode (no persistence, no API) — reason: {DB_UNAVAILABLE_REASON}")
        return
    conn = db_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS organizations (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                contact_email TEXT,
                created_at TIMESTAMPTZ DEFAULT now()
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id SERIAL PRIMARY KEY,
                org_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
                key_hash TEXT UNIQUE NOT NULL,
                key_prefix TEXT NOT NULL,
                label TEXT,
                created_at TIMESTAMPTZ DEFAULT now(),
                last_used_at TIMESTAMPTZ,
                revoked BOOLEAN DEFAULT false
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                org_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                name TEXT,
                role TEXT DEFAULT 'member',
                created_at TIMESTAMPTZ DEFAULT now()
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                created_at TIMESTAMPTZ DEFAULT now(),
                expires_at TIMESTAMPTZ NOT NULL
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                token TEXT PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                created_at TIMESTAMPTZ DEFAULT now(),
                expires_at TIMESTAMPTZ NOT NULL,
                used BOOLEAN DEFAULT false
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS end_users (
                id SERIAL PRIMARY KEY,
                org_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
                external_id TEXT NOT NULL,
                name TEXT,
                created_at TIMESTAMPTZ DEFAULT now(),
                UNIQUE(org_id, external_id)
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS wallets (
                id SERIAL PRIMARY KEY,
                org_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
                end_user_id INTEGER REFERENCES end_users(id) ON DELETE CASCADE,
                address TEXT NOT NULL,
                name TEXT,
                chain TEXT,
                lookback INTEGER DEFAULT 1000,
                last_block BIGINT,
                last_scan_time TEXT,
                reconcile_baseline_balance NUMERIC,
                reconcile_baseline_set_at TEXT,
                reconcile_baseline_tx_count INTEGER,
                created_at TIMESTAMPTZ DEFAULT now(),
                UNIQUE(org_id, address, chain)
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id SERIAL PRIMARY KEY,
                org_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
                wallet_id INTEGER REFERENCES wallets(id) ON DELETE CASCADE,
                tx_hash TEXT NOT NULL,
                block_number BIGINT,
                tx_date TEXT,
                direction TEXT,
                amount NUMERIC,
                counterparty TEXT,
                gas NUMERIC DEFAULT 0,
                asset TEXT DEFAULT 'USDC',
                source TEXT DEFAULT 'blockchain',
                gl_code TEXT,
                confidence NUMERIC,
                classified_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ DEFAULT now(),
                UNIQUE(wallet_id, tx_hash)
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS counterparty_mappings (
                id SERIAL PRIMARY KEY,
                org_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
                end_user_id INTEGER REFERENCES end_users(id) ON DELETE CASCADE,
                counterparty TEXT NOT NULL,
                gl_code TEXT NOT NULL,
                updated_at TIMESTAMPTZ DEFAULT now(),
                UNIQUE(org_id, counterparty)
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS chart_of_accounts (
                id SERIAL PRIMARY KEY,
                org_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
                code TEXT NOT NULL,
                name TEXT NOT NULL,
                account_type TEXT,
                description TEXT,
                created_at TIMESTAMPTZ DEFAULT now(),
                UNIQUE(org_id, code)
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id SERIAL PRIMARY KEY,
                org_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
                end_user_id INTEGER REFERENCES end_users(id) ON DELETE CASCADE,
                log_type TEXT,
                action TEXT,
                detail TEXT,
                created_at TIMESTAMPTZ DEFAULT now()
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS beta_signups (
                id SERIAL PRIMARY KEY,
                name TEXT,
                email TEXT NOT NULL,
                firm_name TEXT,
                message TEXT,
                created_at TIMESTAMPTZ DEFAULT now()
            );
        """)
        conn.commit()
        cur.close()
        print("  [DB] Multi-tenant schema ready.")
    except Exception as e:
        print(f"  [DB] Schema init error: {e}")
        conn.rollback()
    finally:
        db_release(conn)


# ---------- API key auth ----------
def generate_api_key():
    """Returns (full_key, key_hash, key_prefix). Only the hash is stored — the full
    key is shown to the customer exactly once, the same pattern Stripe/GitHub use."""
    raw = secrets.token_urlsafe(32)
    full_key = f"shep_live_{raw}"
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()
    key_prefix = full_key[:14]
    return full_key, key_hash, key_prefix


def create_organization(name, contact_email):
    conn = db_conn()
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO organizations (name, contact_email) VALUES (%s, %s) RETURNING id",
                     (name, contact_email))
        org_id = cur.fetchone()[0]
        full_key, key_hash, key_prefix = generate_api_key()
        cur.execute("INSERT INTO api_keys (org_id, key_hash, key_prefix, label) VALUES (%s, %s, %s, %s)",
                     (org_id, key_hash, key_prefix, "Default key"))
        conn.commit()
        cur.close()
        return {"success": True, "org_id": org_id, "api_key": full_key}
    except Exception as e:
        conn.rollback()
        return {"success": False, "message": str(e)[:200]}
    finally:
        db_release(conn)


def get_org_from_api_key(api_key):
    if not api_key or not DB_AVAILABLE:
        return None
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    conn = db_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT o.id, o.name FROM api_keys k JOIN organizations o ON o.id = k.org_id
            WHERE k.key_hash = %s AND k.revoked = false
        """, (key_hash,))
        row = cur.fetchone()
        if row:
            cur.execute("UPDATE api_keys SET last_used_at = now() WHERE key_hash = %s", (key_hash,))
            conn.commit()
        cur.close()
        return dict(row) if row else None
    finally:
        db_release(conn)


# ---------- Web app session auth (separate from API key auth above, same org model) ----------
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex()
    return pw_hash, salt


def verify_password(password, salt, stored_hash):
    computed, _ = hash_password(password, salt)
    return hmac.compare_digest(computed, stored_hash)


def create_web_session(user_id):
    token = secrets.token_urlsafe(32)
    conn = db_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO sessions (token, user_id, expires_at) VALUES (%s, %s, now() + interval '30 days')",
            (token, user_id)
        )
        conn.commit()
        cur.close()
        return token
    finally:
        db_release(conn)


def get_user_from_session(token):
    if not token or not DB_AVAILABLE:
        return None
    conn = db_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT u.id, u.org_id, u.email, u.name, u.role, o.name as org_name
            FROM sessions s JOIN users u ON u.id = s.user_id JOIN organizations o ON o.id = u.org_id
            WHERE s.token = %s AND s.expires_at > now()
        """, (token,))
        row = cur.fetchone()
        cur.close()
        return dict(row) if row else None
    finally:
        db_release(conn)


def signup_new_org(org_name, email, password, name):
    """Signup creates a brand new organization with this user as its first member.
    Adding teammates to an existing org is a separate, later flow (invite links)."""
    conn = db_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cur.fetchone():
            cur.close()
            return {"success": False, "message": "An account with this email already exists."}

        cur.execute("INSERT INTO organizations (name, contact_email) VALUES (%s, %s) RETURNING id",
                     (org_name, email))
        org_id = cur.fetchone()[0]

        pw_hash, salt = hash_password(password)
        cur.execute(
            "INSERT INTO users (org_id, email, password_hash, salt, name, role) VALUES (%s, %s, %s, %s, %s, 'owner') RETURNING id",
            (org_id, email, pw_hash, salt, name)
        )
        user_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        print(f"  [Signup] Created organization id={org_id} ({org_name}), user id={user_id} ({email})")
        token = create_web_session(user_id)
        return {"success": True, "token": token, "user": {"id": user_id, "org_id": org_id, "email": email, "name": name, "org_name": org_name}}
    except Exception as e:
        conn.rollback()
        print(f"  [Signup] FAILED: {e}")
        return {"success": False, "message": str(e)[:200]}
    finally:
        db_release(conn)


def login_user(email, password):
    conn = db_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT u.id, u.org_id, u.email, u.name, u.password_hash, u.salt, o.name as org_name
            FROM users u JOIN organizations o ON o.id = u.org_id WHERE u.email = %s
        """, (email,))
        row = cur.fetchone()
        cur.close()
        if not row or not verify_password(password, row["salt"], row["password_hash"]):
            print(f"  [Login] FAILED for {email} — {'no such user' if not row else 'wrong password'}")
            return {"success": False, "message": "Invalid email or password."}
        token = create_web_session(row["id"])
        print(f"  [Login] Success: user id={row['id']} org_id={row['org_id']} ({email})")
        return {"success": True, "token": token, "user": {"id": row["id"], "org_id": row["org_id"], "email": row["email"], "name": row["name"], "org_name": row["org_name"]}}
    except Exception as e:
        return {"success": False, "message": str(e)[:200]}
    finally:
        db_release(conn)

def find_or_create_user_by_google(email, name):
    """Log in an existing user by email, or create a brand-new org for them if this
    is their first time — same auto-provisioning behavior as email/password signup,
    just skipping the password step since Google already verified their identity."""
    conn = db_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT u.id, u.org_id, u.email, u.name, o.name as org_name
            FROM users u JOIN organizations o ON o.id = u.org_id WHERE u.email = %s
        """, (email,))
        row = cur.fetchone()
        cur.close()
        if row:
            token = create_web_session(row["id"])
            return {"success": True, "token": token, "user": dict(row)}
    finally:
        db_release(conn)

    # No existing account for this email - provision a new org, same as signup.
    org_name_guess = (email.split("@")[1].split(".")[0].capitalize() if "@" in email else "New Organization")
    random_password = secrets.token_urlsafe(24)  # Google-only accounts never use this, but the column is NOT NULL
    result = signup_new_org(org_name_guess, email, random_password, name)
    if result["success"]:
        send_welcome_email(email, name, org_name_guess)
    return result


# ---------- Core data operations (all org-scoped) ----------
def db_get_or_create_end_user(org_id, external_id, name=None):
    if not external_id:
        return None
    conn = db_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO end_users (org_id, external_id, name) VALUES (%s, %s, %s)
            ON CONFLICT (org_id, external_id) DO UPDATE SET name = COALESCE(EXCLUDED.name, end_users.name)
            RETURNING id
        """, (org_id, external_id, name))
        end_user_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        return end_user_id
    except Exception as e:
        conn.rollback()
        print(f"  [DB] get_or_create_end_user error: {e}")
        return None
    finally:
        db_release(conn)


def db_save_wallet_v1(org_id, end_user_id, address, name, chain, lookback):
    conn = db_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO wallets (org_id, end_user_id, address, name, chain, lookback)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (org_id, address, chain) DO UPDATE SET name = EXCLUDED.name, end_user_id = EXCLUDED.end_user_id
            RETURNING id
        """, (org_id, end_user_id, address, name, chain, lookback))
        wallet_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        print(f"  [DB] Saved wallet id={wallet_id} org_id={org_id} address={address} chain={chain}")
        return wallet_id
    except Exception as e:
        conn.rollback()
        print(f"  [DB] save_wallet_v1 error: {e}")
        return None
    finally:
        db_release(conn)


def db_get_wallet(org_id, wallet_id):
    conn = db_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM wallets WHERE id = %s AND org_id = %s", (wallet_id, org_id))
        row = cur.fetchone()
        cur.close()
        return dict(row) if row else None
    finally:
        db_release(conn)


def db_list_wallets(org_id, end_user_external_id=None):
    conn = db_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        if end_user_external_id:
            cur.execute("""
                SELECT w.* FROM wallets w JOIN end_users u ON u.id = w.end_user_id
                WHERE w.org_id = %s AND u.external_id = %s ORDER BY w.created_at
            """, (org_id, end_user_external_id))
        else:
            cur.execute("SELECT * FROM wallets WHERE org_id = %s ORDER BY created_at", (org_id,))
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
        return rows
    finally:
        db_release(conn)


def db_save_transactions_v1(org_id, wallet_id, txs):
    if not txs:
        return 0
    conn = db_conn()
    try:
        cur = conn.cursor()
        count = 0
        for t in txs:
            cur.execute("""
                INSERT INTO transactions (org_id, wallet_id, tx_hash, block_number, tx_date, direction, amount, counterparty, gas, asset, source)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (wallet_id, tx_hash) DO NOTHING
            """, (org_id, wallet_id, t.get("hash"), t.get("block"), t.get("date"),
                  t.get("dir"), t.get("amount"), t.get("cp"), t.get("gas", 0),
                  t.get("asset", "USDC"), t.get("source", "blockchain")))
            count += cur.rowcount
        conn.commit()
        cur.close()
        return count
    except Exception as e:
        conn.rollback()
        print(f"  [DB] save_transactions_v1 error: {e}")
        return 0
    finally:
        db_release(conn)


def db_classify_transaction_v1(org_id, transaction_id, gl_code, confidence=None):
    conn = db_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            UPDATE transactions SET gl_code = %s, confidence = %s, classified_at = now()
            WHERE org_id = %s AND id = %s
        """, (gl_code, confidence, org_id, transaction_id))
        updated = cur.rowcount > 0
        conn.commit()
        cur.close()
        return updated
    except Exception as e:
        conn.rollback()
        print(f"  [DB] classify_v1 error: {e}")
        return False
    finally:
        db_release(conn)


def db_list_transactions(org_id, wallet_id=None, end_user_external_id=None, gl_code=None, limit=500):
    conn = db_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        query = """
            SELECT t.*, w.address as wallet_address, w.chain as wallet_chain, u.external_id as end_user_id
            FROM transactions t
            JOIN wallets w ON w.id = t.wallet_id
            LEFT JOIN end_users u ON u.id = w.end_user_id
            WHERE t.org_id = %s
        """
        params = [org_id]
        if wallet_id:
            query += " AND t.wallet_id = %s"
            params.append(wallet_id)
        if end_user_external_id:
            query += " AND u.external_id = %s"
            params.append(end_user_external_id)
        if gl_code:
            query += " AND t.gl_code = %s"
            params.append(gl_code)
        query += " ORDER BY t.created_at DESC LIMIT %s"
        params.append(limit)
        cur.execute(query, params)
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
        return rows
    finally:
        db_release(conn)


DEFAULT_CHART_OF_ACCOUNTS = [
    {"code": "6110 - Payroll", "description": "Employee and contractor wages, salaries, and payroll-related payments. Often recurring, round amounts on a regular schedule."},
    {"code": "6200 - Software & SaaS", "description": "Subscription software and SaaS tools. Usually small, recurring, fixed amounts."},
    {"code": "6300 - Cloud Infrastructure", "description": "Cloud infrastructure and hosting costs. Often usage-based, may vary month to month."},
    {"code": "6420 - Marketing & Ads", "description": "Marketing, advertising, and paid promotion spend."},
    {"code": "6500 - Professional Services", "description": "Payments to lawyers, accountants, consultants, auditors, and other professional service providers."},
    {"code": "6600 - Office & Operations", "description": "General office expenses and operational overhead not covered by other categories."},
    {"code": "7100 - Intercompany Transfer", "description": "Transfers between the company's own wallets or accounts — not a real expense or revenue event."},
    {"code": "4100 - Revenue - Services", "description": "Revenue from services rendered to clients or customers."},
    {"code": "4200 - Revenue - Product", "description": "Revenue from product sales."},
    {"code": "4300 - Customer Refund", "description": "Refunds issued to customers, recorded as a reduction of revenue."},
]


def db_get_chart_of_accounts(org_id):
    conn = db_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT code, name, description FROM chart_of_accounts WHERE org_id = %s", (org_id,))
        rows = cur.fetchall()
        cur.close()
        if not rows:
            return DEFAULT_CHART_OF_ACCOUNTS
        return [{"code": f"{r['code']} - {r['name']}", "description": r.get("description", "")} for r in rows]
    finally:
        db_release(conn)


def db_save_chart_of_accounts_entry(org_id, code, name, account_type, description=""):
    conn = db_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO chart_of_accounts (org_id, code, name, account_type, description)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (org_id, code) DO UPDATE SET name = EXCLUDED.name, account_type = EXCLUDED.account_type, description = EXCLUDED.description
        """, (org_id, code, name, account_type, description))
        conn.commit()
        cur.close()
        return True
    except Exception as e:
        conn.rollback()
        print(f"  [DB] save_coa_entry error: {e}")
        return False
    finally:
        db_release(conn)


def db_list_audit_log(org_id, limit=300):
    conn = db_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM audit_log WHERE org_id = %s ORDER BY created_at DESC LIMIT %s", (org_id, limit))
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
        return rows
    finally:
        db_release(conn)


def db_get_counterparty_mappings(org_id):
    conn = db_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT counterparty, gl_code FROM counterparty_mappings WHERE org_id = %s", (org_id,))
        rows = cur.fetchall()
        cur.close()
        return {r["counterparty"]: r["gl_code"] for r in rows}
    finally:
        db_release(conn)


def db_save_counterparty_mapping(org_id, end_user_id, counterparty, gl_code):
    conn = db_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO counterparty_mappings (org_id, end_user_id, counterparty, gl_code)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (org_id, counterparty) DO UPDATE SET gl_code = EXCLUDED.gl_code, end_user_id = EXCLUDED.end_user_id, updated_at = now()
        """, (org_id, end_user_id, counterparty, gl_code))
        conn.commit()
        cur.close()
        return True
    except Exception as e:
        conn.rollback()
        print(f"  [DB] save_counterparty_mapping error: {e}")
        return False
    finally:
        db_release(conn)


def db_get_prior_context(org_id, end_user_id, exclude_wallet_id=None):
    """Build the same {counterparty, gl_code, count, avg_amount, direction, pattern}
    shape the web app's AI prompt expects, from this org's (or end user's) classified history."""
    conn = db_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT t.counterparty, t.gl_code, t.direction, t.amount
            FROM transactions t JOIN wallets w ON w.id = t.wallet_id
            WHERE t.org_id = %s AND t.gl_code IS NOT NULL
            AND (%s::int IS NULL OR w.end_user_id = %s)
        """, (org_id, end_user_id, end_user_id))
        rows = cur.fetchall()
        cur.close()
    finally:
        db_release(conn)

    stats = {}
    for r in rows:
        cp = r["counterparty"]
        if cp not in stats:
            stats[cp] = {"counterparty": cp, "gl_code": r["gl_code"], "direction": r["direction"], "count": 0, "total": 0.0, "amounts": []}
        stats[cp]["count"] += 1
        stats[cp]["total"] += float(r["amount"] or 0)
        stats[cp]["amounts"].append(float(r["amount"] or 0))

    out = []
    for cp, s in stats.items():
        pattern = ""
        if s["count"] > 2:
            pattern = "recurring fixed" if all(abs(a - s["amounts"][0]) < 1 for a in s["amounts"]) else "recurring variable"
        out.append({"counterparty": cp, "gl_code": s["gl_code"], "count": s["count"],
                     "avg_amount": s["total"] / s["count"], "direction": s["direction"], "pattern": pattern})
    return out


def auto_classify_new_transactions(org_id, wallet_id, end_user_id, chain_label, confidence_threshold=0.80):
    """Run AI classification over every not-yet-classified transaction on this wallet,
    auto-applying the GL code when confidence clears the threshold. Always stores the
    AI's suggestion + confidence even below threshold, so the API consumer can see it."""
    conn = db_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM transactions WHERE org_id = %s AND wallet_id = %s AND gl_code IS NULL", (org_id, wallet_id))
        pending = [dict(r) for r in cur.fetchall()]
        cur.close()
    finally:
        db_release(conn)

    if not pending:
        return {"classified": 0, "reviewed": 0}

    coa = db_get_chart_of_accounts(org_id)
    classified_count = 0

    for t in pending:
        prior = db_get_prior_context(org_id, end_user_id)
        tx_data = {
            "direction": t["direction"], "amount": float(t["amount"] or 0), "asset": t.get("asset", "USDC"),
            "counterparty": t["counterparty"], "chain": chain_label, "block": t.get("block_number"),
            "source": t.get("source", "blockchain")
        }
        try:
            result = classify_transaction(tx_data, coa, prior, client_profile=None)
        except Exception as e:
            print(f"  [Auto-classify] Error classifying tx {t['id']}: {e}")
            continue
        gl_code = result.get("gl_code")
        confidence = result.get("confidence", 0)
        if gl_code and confidence >= confidence_threshold:
            db_classify_transaction_v1(org_id, t["id"], gl_code, confidence)
            classified_count += 1
        else:
            # Store the suggestion + confidence without marking it classified, so the
            # API consumer can see what Shepherd thinks even when it's not confident enough to auto-apply.
            conn2 = db_conn()
            try:
                cur2 = conn2.cursor()
                cur2.execute("UPDATE transactions SET confidence = %s WHERE id = %s", (confidence, t["id"]))
                conn2.commit()
                cur2.close()
            except Exception:
                conn2.rollback()
            finally:
                db_release(conn2)

    return {"classified": classified_count, "reviewed": len(pending)}


def db_financial_statements(org_id, wallet_id=None, end_user_external_id=None):
    """Compute a simple P&L summary from classified transactions. Balance sheet /
    cash flow depth matches the same on-the-fly calculation approach the web app uses,
    kept intentionally simple here as the v1 API surface."""
    txs = db_list_transactions(org_id, wallet_id=wallet_id, end_user_external_id=end_user_external_id, limit=10000)
    revenue = {}
    expenses = {}
    unclassified_in = 0.0
    unclassified_out = 0.0
    for t in txs:
        gl = t.get("gl_code")
        amt = float(t.get("amount") or 0)
        if not gl:
            if t["direction"] == "inflow":
                unclassified_in += amt
            else:
                unclassified_out += amt
            continue
        bucket = revenue if gl.split(" ")[0].startswith(("4",)) else expenses
        bucket[gl] = bucket.get(gl, 0) + amt
    total_revenue = sum(revenue.values())
    total_expenses = sum(expenses.values())
    return {
        "revenue": revenue,
        "expenses": expenses,
        "total_revenue": round(total_revenue, 2),
        "total_expenses": round(total_expenses, 2),
        "net_income": round(total_revenue - total_expenses, 2),
        "unclassified_inflow": round(unclassified_in, 2),
        "unclassified_outflow": round(unclassified_out, 2),
        "transaction_count": len(txs),
        "classified_count": sum(1 for t in txs if t.get("gl_code")),
    }


def db_save_audit_entry_v1(org_id, end_user_id, log_type, action, detail):
    conn = db_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO audit_log (org_id, end_user_id, log_type, action, detail) VALUES (%s, %s, %s, %s, %s)",
            (org_id, end_user_id, log_type, action, detail)
        )
        conn.commit()
        cur.close()
    except Exception as e:
        conn.rollback()
        print(f"  [DB] audit_log_v1 error: {e}")
    finally:
        db_release(conn)


db_init_schema()


# ======================== SCANNER (self-contained) ========================
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

# Verified contract addresses (Circle docs + Etherscan, checked live).
# decimals: USDC/USDT/PYUSD/USDP = 6, DAI/EURC = varies — see per-token entries below.
EVM_CHAINS = {
    "base": {
        "label": "Base",
        "explorer": "https://basescan.org/tx/",
        "rpc_url": os.environ.get("BASE_RPC_URL", "https://base-mainnet.g.alchemy.com/v2/j5z3ffA4ndMffb9Me4jLt").strip(),
        "tokens": {
            "USDC": {"contract": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "decimals": 6},
            "EURC": {"contract": "0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42", "decimals": 6},
        },
    },
    "ethereum": {
        "label": "Ethereum",
        "explorer": "https://etherscan.io/tx/",
        "rpc_url": os.environ.get("ETHEREUM_RPC_URL", "https://eth-mainnet.g.alchemy.com/v2/j5z3ffA4ndMffb9Me4jLt").strip(),
        "tokens": {
            "USDC": {"contract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", "decimals": 6},
            "USDT": {"contract": "0xdac17f958d2ee523a2206206994597c13d831ec7", "decimals": 6},
            "DAI":  {"contract": "0x6b175474e89094c44da98b954eedeac495271d0f", "decimals": 18},
            "USDP": {"contract": "0x8e870d67f660d95d5be530380d0ec0bd388289e1", "decimals": 18},
            "PYUSD": {"contract": "0x6c3ea9036406852006290770bedfcaba0e23a0e8", "decimals": 6},
            "EURC": {"contract": "0x1abaea1f7c830bd89acc67ec4af516284b1bc33c", "decimals": 6},
        },
    },
    "polygon": {
        "label": "Polygon",
        "explorer": "https://polygonscan.com/tx/",
        "rpc_url": os.environ.get("POLYGON_RPC_URL", "https://polygon-mainnet.g.alchemy.com/v2/j5z3ffA4ndMffb9Me4jLt").strip(),
        "tokens": {
            "USDC": {"contract": "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359", "decimals": 6},
            "DAI":  {"contract": "0x8f3cf7ad23cd3cadbd9735aff958023239c6a063", "decimals": 18},
        },
    },
}


class EVMStablecoinLedger:
    """Generalized EVM scanner. Works for Base, Ethereum, Polygon (or any EVM chain
    added to EVM_CHAINS above) and scans every configured stablecoin on that chain
    in a single pass, tagging each transfer with which token it actually was."""

    TRANSFER_TOPIC = TRANSFER_TOPIC

    def __init__(self, watched_wallet, chain_key="base", eth_usd_price=1700.00, chunk_size=10):
        if chain_key not in EVM_CHAINS:
            raise ValueError(f"Unknown EVM chain: {chain_key}")
        self.chain_key = chain_key
        self.chain = EVM_CHAINS[chain_key]
        self.RPC_URL = self.chain["rpc_url"]
        self.tokens = self.chain["tokens"]
        self.watched_wallet = watched_wallet.lower()
        self.eth_usd_price = eth_usd_price
        self.chunk_size = chunk_size
        self._receipt_cache = {}
        self.progress = {"phase": "", "pct": 0, "found": 0}

    def _rpc(self, method, params, retries=3):
        payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
        body = json.dumps(payload).encode("utf-8")
        last_err = None
        for attempt in range(retries):
            try:
                req = urllib.request.Request(self.RPC_URL, data=body,
                    headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    result = json.loads(resp.read().decode())
                if "error" in result:
                    err_msg = str(result["error"].get("message", result["error"]))
                    if "is not enabled for this app" in err_msg:
                        chain_label = self.chain.get("label", self.chain_key)
                        raise RuntimeError(
                            f"{chain_label} isn't enabled on your Alchemy app yet. "
                            f"Add it in the Alchemy dashboard under this app's Networks settings, "
                            f"then try again — no code change needed."
                        )
                    raise RuntimeError(f"RPC error: {result['error']}")
                return result.get("result")
            except urllib.error.HTTPError as e:
                err_body = e.read().decode() if hasattr(e, 'read') else ""
                if "is not enabled for this app" in err_body:
                    chain_label = self.chain.get("label", self.chain_key)
                    raise RuntimeError(
                        f"{chain_label} isn't enabled on your Alchemy app yet. "
                        f"Add it in the Alchemy dashboard under this app's Networks settings, "
                        f"then try again — no code change needed."
                    )
                last_err = f"HTTP {e.code}: {err_body[:200]}"
                time.sleep(0.5 * (2 ** attempt))
            except (urllib.error.URLError, TimeoutError) as e:
                last_err = e
                time.sleep(0.5 * (2 ** attempt))
        raise RuntimeError(f"RPC failed after {retries} retries: {last_err}")

    @staticmethod
    def _addr_to_topic(addr):
        return "0x" + ("0" * 24) + addr.lower().replace("0x", "")

    @staticmethod
    def _topic_to_addr(topic):
        return "0x" + topic[-40:].lower()

    def latest_block(self):
        return int(self._rpc("eth_blockNumber", []), 16)

    def get_current_balance(self, address, token_symbol="USDC"):
        """Query the live on-chain balance of a given token for a wallet via balanceOf(address)."""
        token = self.tokens.get(token_symbol)
        if not token:
            return 0.0
        addr_padded = address.lower().replace("0x", "").rjust(64, "0")
        data = "0x70a08231" + addr_padded  # balanceOf(address) selector
        result = self._rpc("eth_call", [{"to": token["contract"], "data": data}, "latest"])
        raw = int(result, 16) if result and result != "0x" else 0
        return raw / (10 ** token["decimals"])

    # Backward-compat alias used by the reconciliation feature
    def get_current_usdc_balance(self, address):
        return self.get_current_balance(address, "USDC")

    def _get_logs_chunked(self, from_block, to_block, contract, topics, label=""):
        out = []
        cur = from_block
        total = to_block - from_block + 1
        while cur <= to_block:
            end = min(cur + self.chunk_size - 1, to_block)
            done = cur - from_block
            pct = int(done / total * 100) if total > 0 else 100
            self.progress = {"phase": label, "pct": pct, "found": len(out)}
            logs = self._rpc("eth_getLogs", [{
                "address": contract, "topics": topics,
                "fromBlock": hex(cur), "toBlock": hex(end),
            }])
            if logs:
                out.extend(logs)
            cur = end + 1
        self.progress = {"phase": label, "pct": 100, "found": len(out)}
        return out

    def scan_token_transfers(self, from_block, to_block, token_symbol):
        token = self.tokens[token_symbol]
        wallet_topic = self._addr_to_topic(self.watched_wallet)
        outflows = self._get_logs_chunked(from_block, to_block, token["contract"],
            topics=[self.TRANSFER_TOPIC, wallet_topic], label=f"{token_symbol} outflows")
        inflows = self._get_logs_chunked(from_block, to_block, token["contract"],
            topics=[self.TRANSFER_TOPIC, None, wallet_topic], label=f"{token_symbol} inflows")
        transfers = []
        for log in outflows:
            transfers.append(self._decode_log(log, "outflow", token_symbol, token["decimals"]))
        for log in inflows:
            transfers.append(self._decode_log(log, "inflow", token_symbol, token["decimals"]))
        return transfers

    def _decode_log(self, log, direction, token_symbol, decimals):
        topics = log["topics"]
        return {
            "direction": direction,
            "asset": token_symbol,
            "from": self._topic_to_addr(topics[1]),
            "to": self._topic_to_addr(topics[2]),
            "amount": int(log["data"], 16) / (10 ** decimals),
            "tx_hash": log["transactionHash"],
            "block_number": int(log["blockNumber"], 16),
            "log_index": int(log["logIndex"], 16),
        }

    def _receipt(self, tx_hash):
        if tx_hash in self._receipt_cache:
            return self._receipt_cache[tx_hash]
        r = self._rpc("eth_getTransactionReceipt", [tx_hash])
        self._receipt_cache[tx_hash] = r
        return r

    def _gas_usd_for_outflow(self, tx_hash):
        r = self._receipt(tx_hash)
        if not r or r.get("status") != "0x1":
            return 0.0, 0.0
        gas_used = int(r.get("gasUsed", "0x0"), 16)
        gas_price = int(r.get("effectiveGasPrice", "0x0"), 16)
        gas_eth = (gas_used * gas_price) / 10**18
        return gas_eth, round(gas_eth * self.eth_usd_price, 6)

    def compile_journal(self, transfer):
        amt = round(transfer["amount"], 2)
        asset = transfer["asset"]
        chain_label = self.chain["label"]
        asset_account = f"Digital Asset - {asset} ({chain_label})"
        counterparty = transfer["to"] if transfer["direction"] == "outflow" else transfer["from"]
        if transfer["direction"] == "outflow":
            gas_eth, gas_usd = self._gas_usd_for_outflow(transfer["tx_hash"])
            lines = [
                {"line": 1, "account": "AP / Expense (unclassified)", "debit": amt, "credit": 0.0,
                 "memo": f"{asset} out to {counterparty}"},
                {"line": 2, "account": asset_account, "debit": 0.0, "credit": amt,
                 "memo": f"{asset} sent"},
            ]
            if gas_usd > 0:
                lines += [
                    {"line": 3, "account": "Expense - Network Fees", "debit": gas_usd, "credit": 0.0,
                     "memo": f"Gas {gas_eth:.8f} ETH @ ${self.eth_usd_price}"},
                    {"line": 4, "account": f"Digital Asset - ETH (gas, {chain_label})", "debit": 0.0, "credit": gas_usd,
                     "memo": "Gas consumed"},
                ]
        else:
            lines = [
                {"line": 1, "account": asset_account, "debit": amt, "credit": 0.0,
                 "memo": f"{asset} in from {counterparty}"},
                {"line": 2, "account": "AR / Revenue (unclassified)", "debit": 0.0, "credit": amt,
                 "memo": f"{asset} received"},
            ]
            gas_eth, gas_usd = 0.0, 0.0

        total_debit = round(sum(l["debit"] for l in lines), 2)
        total_credit = round(sum(l["credit"] for l in lines), 2)
        return {
            "tx_hash": transfer["tx_hash"],
            "block_number": transfer["block_number"],
            "direction": transfer["direction"],
            "asset": asset,
            "chain": self.chain_key,
            "amount": amt,
            "counterparty": counterparty,
            "gas_usd": gas_usd,
            "total_debit": total_debit,
            "total_credit": total_credit,
            "is_balanced": total_debit == total_credit,
            "journal_lines": lines,
        }

    def build_report(self, from_block, to_block):
        all_transfers = []
        for token_symbol in self.tokens:
            all_transfers.extend(self.scan_token_transfers(from_block, to_block, token_symbol))
        all_transfers.sort(key=lambda t: (t["block_number"], t["log_index"]))

        self.progress = {"phase": "Building journals", "pct": 50, "found": len(all_transfers)}
        journals = []
        for i, t in enumerate(all_transfers):
            journals.append(self.compile_journal(t))
            if len(all_transfers) > 0:
                self.progress = {"phase": "Building journals", "pct": 50 + int(50 * i / len(all_transfers)), "found": len(all_transfers)}

        total_in = round(sum(j["amount"] for j in journals if j["direction"] == "inflow"), 2)
        total_out = round(sum(j["amount"] for j in journals if j["direction"] == "outflow"), 2)
        total_gas = round(sum(j["gas_usd"] for j in journals), 6)
        self.progress = {"phase": "Done", "pct": 100, "found": len(all_transfers)}
        return {
            "wallet": self.watched_wallet,
            "chain": self.chain_key,
            "scan_range": {"from_block": from_block, "to_block": to_block},
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "transfer_count": len(journals),
                "inflow_count": sum(1 for j in journals if j["direction"] == "inflow"),
                "outflow_count": sum(1 for j in journals if j["direction"] == "outflow"),
                "total_usdc_in": total_in,
                "total_usdc_out": total_out,
                "net_usdc": round(total_in - total_out, 2),
                "total_gas_usd": total_gas,
                "all_balanced": all(j["is_balanced"] for j in journals),
            },
            "journals": journals,
        }


# Backward-compat: existing code that instantiates BaseStablecoinLedger(wallet) still works,
# defaulting to the Base chain.
class BaseStablecoinLedger(EVMStablecoinLedger):
    def __init__(self, watched_wallet, eth_usd_price=1700.00, chunk_size=10):
        super().__init__(watched_wallet, chain_key="base", eth_usd_price=eth_usd_price, chunk_size=chunk_size)


# ======================== SOLANA SCANNER ========================

SOLANA_TOKENS = {
    "USDC": {"mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "decimals": 6},
    "EURC": {"mint": "HzwqbKZw8HxMN6bF2yFZNrht3c2iXXzpKcFu7uBEDKtr", "decimals": 6},
}


class SolanaStablecoinLedger:
    RPC_URL = os.environ.get("SOLANA_RPC_URL", "https://mainnet.helius-rpc.com/?api-key=8344d6de-09ea-425c-a80b-9696150a7c43").strip()
    SOL_USD_PRICE = 70

    def __init__(self, watched_wallet, tx_limit=50):
        self.watched_wallet = str(watched_wallet).strip()
        self.tx_limit = tx_limit
        self.tokens = SOLANA_TOKENS
        self.progress = {"phase": "", "pct": 0, "found": 0}

    def _rpc(self, method, params, retries=3):
        payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
        body = json.dumps(payload).encode("utf-8")
        last_err = None
        for attempt in range(retries):
            try:
                req = urllib.request.Request(self.RPC_URL, data=body,
                    headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=20) as resp:
                    result = json.loads(resp.read().decode())
                if "error" in result:
                    print(f"  [Solana RPC ERROR] method={method}")
                    print(f"  [Solana RPC ERROR] params sent: {json.dumps(params)[:500]}")
                    print(f"  [Solana RPC ERROR] response: {result['error']}")
                    raise RuntimeError(f"RPC error: {result['error']}")
                return result.get("result")
            except urllib.error.HTTPError as e:
                err_body = e.read().decode() if hasattr(e, 'read') else ""
                print(f"  [Solana RPC HTTP ERROR] method={method} status={e.code}")
                print(f"  [Solana RPC HTTP ERROR] params sent: {json.dumps(params)[:500]}")
                print(f"  [Solana RPC HTTP ERROR] body: {err_body[:500]}")
                last_err = f"HTTP {e.code}: {err_body[:200]}"
                time.sleep(1.0 * (2 ** attempt))
            except (urllib.error.URLError, TimeoutError) as e:
                last_err = e
                time.sleep(1.0 * (2 ** attempt))
        raise RuntimeError(f"Solana RPC failed after {retries} retries: {last_err}")

    def get_current_balance(self, address=None, token_symbol="USDC"):
        """Query the live on-chain balance of a given token for a wallet via getTokenAccountsByOwner."""
        wallet = address or self.watched_wallet
        token = self.tokens.get(token_symbol)
        if not token:
            return 0.0
        result = self._rpc("getTokenAccountsByOwner", [
            wallet,
            {"mint": token["mint"]},
            {"encoding": "jsonParsed"}
        ])
        if not result or not result.get("value"):
            return 0.0
        total = 0.0
        for acct in result["value"]:
            try:
                amt = acct["account"]["data"]["parsed"]["info"]["tokenAmount"]["uiAmount"]
                total += float(amt or 0)
            except (KeyError, TypeError):
                continue
        return total

    # Backward-compat alias used by the reconciliation feature
    def get_current_usdc_balance(self, address=None):
        return self.get_current_balance(address, "USDC")

    def scan_token_transfers(self):
        self.progress = {"phase": "Fetching signatures", "pct": 2, "found": 0}

        # Paginate: Solana caps at 1000 per call
        all_sigs = []
        remaining = self.tx_limit
        before = None
        while remaining > 0:
            batch_size = min(remaining, 1000)
            params = {"limit": batch_size}
            if before:
                params["before"] = before
            sigs = self._rpc("getSignaturesForAddress", [self.watched_wallet, params])
            if not sigs:
                break
            all_sigs.extend(sigs)
            before = sigs[-1]["signature"]
            remaining -= len(sigs)
            self.progress = {"phase": "Fetching signatures", "pct": 2, "found": len(all_sigs)}
            if len(sigs) < batch_size:
                break  # no more history

        if not all_sigs:
            return []

        transfers = []
        total = len(all_sigs)
        for i, sig_info in enumerate(all_sigs):
            pct = int((i / total) * 93) + 5
            self.progress = {"phase": "Parsing transactions", "pct": pct, "found": len(transfers)}

            if sig_info.get("err"):
                continue  # skip failed txs

            try:
                tx = self._rpc("getTransaction", [
                    sig_info["signature"],
                    {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}
                ])
            except Exception:
                continue

            if not tx or not tx.get("meta"):
                continue

            transfers.extend(self._extract_token_transfers(tx, sig_info["signature"]))

        self.progress = {"phase": "Done", "pct": 100, "found": len(transfers)}
        transfers.sort(key=lambda t: t["slot"])
        return transfers

    def _extract_token_transfers(self, tx, signature):
        """Extract stablecoin transfers (any configured mint) from a parsed Solana transaction.
        Usually one token moves per tx, but this returns a list to handle multi-token txs too."""
        meta = tx["meta"]
        pre_tokens = meta.get("preTokenBalances") or []
        post_tokens = meta.get("postTokenBalances") or []
        slot = tx.get("slot", 0)

        # Fee in SOL, attributed only if our wallet is the fee payer
        fee_lamports = meta.get("fee", 0)
        fee_sol = fee_lamports / 1e9
        fee_usd = round(fee_sol * self.SOL_USD_PRICE, 6)
        account_keys = []
        msg = tx.get("transaction", {}).get("message", {})
        for ak in msg.get("accountKeys", []):
            account_keys.append(ak.get("pubkey", "") if isinstance(ak, dict) else ak)
        is_signer = len(account_keys) > 0 and account_keys[0] == self.watched_wallet

        results = []
        for token_symbol, token in self.tokens.items():
            def token_map(balances, mint=token["mint"]):
                m = {}
                for b in balances:
                    if b.get("mint") == mint:
                        owner = b.get("owner", "")
                        amt = float(b.get("uiTokenAmount", {}).get("uiAmount") or 0)
                        m[owner] = amt
                return m

            pre = token_map(pre_tokens)
            post = token_map(post_tokens)

            pre_bal = pre.get(self.watched_wallet, 0)
            post_bal = post.get(self.watched_wallet, 0)
            delta = round(post_bal - pre_bal, 2)

            if abs(delta) < 0.01:
                continue  # no meaningful change for this token in this tx

            direction = "inflow" if delta > 0 else "outflow"
            amount = abs(delta)

            counterparty = "unknown"
            all_owners = set(list(pre.keys()) + list(post.keys()))
            for owner in all_owners:
                if owner == self.watched_wallet:
                    continue
                other_delta = (post.get(owner, 0)) - (pre.get(owner, 0))
                if (direction == "outflow" and other_delta > 0) or \
                   (direction == "inflow" and other_delta < 0):
                    counterparty = owner
                    break

            results.append({
                "direction": direction,
                "asset": token_symbol,
                "from": self.watched_wallet if direction == "outflow" else counterparty,
                "to": counterparty if direction == "outflow" else self.watched_wallet,
                "amount": amount,
                "tx_hash": signature,
                "block_number": slot,
                "slot": slot,
                "log_index": 0,
                "fee_sol": fee_sol if is_signer else 0,
                "fee_usd": fee_usd if is_signer else 0,
            })
        return results

    def compile_journal(self, transfer):
        amt = round(transfer["amount"], 2)
        asset = transfer["asset"]
        cp = transfer["to"] if transfer["direction"] == "outflow" else transfer["from"]
        fee_usd = transfer.get("fee_usd", 0)
        asset_account = f"Digital Asset - {asset} (Solana)"

        if transfer["direction"] == "outflow":
            lines = [
                {"line": 1, "account": "AP / Expense (unclassified)", "debit": amt, "credit": 0.0,
                 "memo": f"{asset} out to {cp[:8]}..."},
                {"line": 2, "account": asset_account, "debit": 0.0, "credit": amt,
                 "memo": f"{asset} sent"},
            ]
            if fee_usd > 0:
                lines += [
                    {"line": 3, "account": "Expense - Network Fees", "debit": fee_usd, "credit": 0.0,
                     "memo": f"Solana fee {transfer['fee_sol']:.6f} SOL @ ${self.SOL_USD_PRICE}"},
                    {"line": 4, "account": "Digital Asset - SOL (gas)", "debit": 0.0, "credit": fee_usd,
                     "memo": "SOL consumed"},
                ]
        else:
            lines = [
                {"line": 1, "account": asset_account, "debit": amt, "credit": 0.0,
                 "memo": f"{asset} in from {cp[:8]}..."},
                {"line": 2, "account": "AR / Revenue (unclassified)", "debit": 0.0, "credit": amt,
                 "memo": f"{asset} received"},
            ]
            fee_usd = 0

        total_debit = round(sum(l["debit"] for l in lines), 2)
        total_credit = round(sum(l["credit"] for l in lines), 2)
        return {
            "tx_hash": transfer["tx_hash"],
            "block_number": transfer.get("slot", 0),
            "direction": transfer["direction"],
            "asset": asset,
            "amount": amt,
            "counterparty": cp,
            "gas_usd": fee_usd,
            "total_debit": total_debit,
            "total_credit": total_credit,
            "is_balanced": total_debit == total_credit,
            "journal_lines": lines,
        }

    def build_report(self):
        transfers = self.scan_token_transfers()
        journals = [self.compile_journal(t) for t in transfers]
        total_in = round(sum(j["amount"] for j in journals if j["direction"] == "inflow"), 2)
        total_out = round(sum(j["amount"] for j in journals if j["direction"] == "outflow"), 2)
        total_gas = round(sum(j["gas_usd"] for j in journals), 6)
        return {
            "wallet": self.watched_wallet,
            "chain": "solana",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "transfer_count": len(journals),
                "inflow_count": sum(1 for j in journals if j["direction"] == "inflow"),
                "outflow_count": sum(1 for j in journals if j["direction"] == "outflow"),
                "total_usdc_in": total_in,
                "total_usdc_out": total_out,
                "net_usdc": round(total_in - total_out, 2),
                "total_gas_usd": total_gas,
                "all_balanced": all(j["is_balanced"] for j in journals),
            },
            "journals": journals,
        }




# ======================== PLAID INTEGRATION (FIAT BANKING) ========================
PLAID_CLIENT_ID = os.environ.get("PLAID_CLIENT_ID", "").strip()
PLAID_SECRET = os.environ.get("PLAID_SECRET", "").strip()
PLAID_ENV = os.environ.get("PLAID_ENV", "sandbox").strip()  # sandbox, development, or production

plaid_items = {}  # access_token keyed by item_id, plus metadata

def plaid_base_url():
    return f"https://{PLAID_ENV}.plaid.com"

def plaid_request(path, payload):
    """Make a POST request to Plaid's REST API with client_id/secret injected."""
    payload = dict(payload)
    payload["client_id"] = PLAID_CLIENT_ID
    payload["secret"] = PLAID_SECRET
    try:
        url = f"{plaid_base_url()}{path}"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return {"success": True, "data": json.loads(resp.read().decode())}
    except urllib.error.HTTPError as e:
        error_body = e.read().decode() if e.fp else str(e)
        return {"success": False, "message": f"Plaid Error {e.code}: {error_body[:300]}"}
    except Exception as e:
        return {"success": False, "message": str(e)[:200]}

def plaid_create_link_token():
    if not PLAID_CLIENT_ID or not PLAID_SECRET:
        return {"success": False, "message": "PLAID_CLIENT_ID / PLAID_SECRET not set"}
    result = plaid_request("/link/token/create", {
        "user": {"client_user_id": "shepherd-demo-user"},
        "client_name": "Shepherd",
        "products": ["transactions"],
        "country_codes": ["US"],
        "language": "en"
    })
    return result

def plaid_exchange_public_token(public_token):
    result = plaid_request("/item/public_token/exchange", {"public_token": public_token})
    if result["success"]:
        access_token = result["data"]["access_token"]
        item_id = result["data"]["item_id"]
        plaid_items[item_id] = {"access_token": access_token}
        return {"success": True, "item_id": item_id}
    return result

def plaid_get_accounts(access_token):
    result = plaid_request("/accounts/get", {"access_token": access_token})
    if result["success"]:
        accounts = result["data"].get("accounts", [])
        return {"success": True, "accounts": [
            {"id": a["account_id"], "name": a.get("name", "Account"),
             "official_name": a.get("official_name", ""), "mask": a.get("mask", ""),
             "type": a.get("type", ""), "subtype": a.get("subtype", ""),
             "balance": a.get("balances", {}).get("current", 0)}
            for a in accounts
        ]}
    return result

def plaid_sync_transactions(access_token, cursor=None):
    """Use /transactions/sync for incremental, reliable transaction fetching."""
    payload = {"access_token": access_token}
    if cursor:
        payload["cursor"] = cursor
    result = plaid_request("/transactions/sync", payload)
    if result["success"]:
        d = result["data"]
        return {
            "success": True,
            "added": d.get("added", []),
            "modified": d.get("modified", []),
            "removed": d.get("removed", []),
            "next_cursor": d.get("next_cursor"),
            "has_more": d.get("has_more", False)
        }
    return result


# ======================== BILL.COM INTEGRATION ========================
BILLCOM_DEV_KEY = os.environ.get("BILLCOM_DEV_KEY", "").strip()
BILLCOM_ORG_ID = os.environ.get("BILLCOM_ORG_ID", "").strip()
BILLCOM_USERNAME = os.environ.get("BILLCOM_USERNAME", "").strip()
BILLCOM_PASSWORD = os.environ.get("BILLCOM_PASSWORD", "").strip()
BILLCOM_ENV = os.environ.get("BILLCOM_ENV", "sandbox").strip()  # sandbox or production

billcom_session = {"sessionId": None, "expires_at": 0}

def billcom_gateway_url():
    if BILLCOM_ENV == "production":
        return "https://gateway.bill.com/connect/v3/login"
    return "https://gateway.stage.bill.com/connect/v3/login"

def billcom_api_base():
    if BILLCOM_ENV == "production":
        return "https://api.bill.com/v3"
    return "https://api-stage.bill.com/v3"

def billcom_login():
    if not (BILLCOM_DEV_KEY and BILLCOM_ORG_ID and BILLCOM_USERNAME and BILLCOM_PASSWORD):
        return {"success": False, "message": "Bill.com credentials not fully configured (devKey/orgId/username/password)"}
    try:
        payload = {
            "username": BILLCOM_USERNAME,
            "password": BILLCOM_PASSWORD,
            "organizationId": BILLCOM_ORG_ID,
            "devKey": BILLCOM_DEV_KEY
        }
        req = urllib.request.Request(
            billcom_gateway_url(),
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        billcom_session["sessionId"] = data.get("sessionId")
        billcom_session["expires_at"] = time.time() + 30 * 60  # session idles out at 35 min, refresh a bit early
        return {"success": True, "organizationId": data.get("organizationId"), "userId": data.get("userId")}
    except urllib.error.HTTPError as e:
        error_body = e.read().decode() if e.fp else str(e)
        return {"success": False, "message": f"Bill.com login error {e.code}: {error_body[:300]}"}
    except Exception as e:
        return {"success": False, "message": str(e)[:200]}

def billcom_ensure_session():
    if billcom_session["sessionId"] and time.time() < billcom_session["expires_at"]:
        return True
    result = billcom_login()
    return result.get("success", False)

def billcom_get_bills():
    if not billcom_ensure_session():
        return {"success": False, "message": "Could not establish Bill.com session"}
    try:
        url = f"{billcom_api_base()}/bills?max=100"
        req = urllib.request.Request(url, headers={
            "sessionId": billcom_session["sessionId"],
            "devKey": BILLCOM_DEV_KEY,
            "Accept": "application/json"
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        bills = data.get("results", data if isinstance(data, list) else [])
        parsed = []
        for b in bills:
            parsed.append({
                "id": b.get("id", ""),
                "vendor": b.get("vendorName", b.get("vendorId", "Unknown vendor")),
                "invoiceNumber": b.get("invoiceNumber", ""),
                "amount": float(b.get("amount", 0) or 0),
                "invoiceDate": b.get("invoiceDate", ""),
                "dueDate": b.get("dueDate", ""),
                "description": b.get("description", "")
            })
        return {"success": True, "bills": parsed}
    except urllib.error.HTTPError as e:
        error_body = e.read().decode() if e.fp else str(e)
        return {"success": False, "message": f"Bill.com error {e.code}: {error_body[:300]}"}
    except Exception as e:
        return {"success": False, "message": str(e)[:200]}


# ======================== EMAIL INVOICE INGESTION ========================
IMAP_HOSTS = {
    "smtp.gmail.com": "imap.gmail.com",
    "smtp.office365.com": "outlook.office365.com",
    "smtp.mail.yahoo.com": "imap.mail.yahoo.com"
}

def scan_email_invoices(smtp_host, email_user, email_pass, days_back=14):
    """Connect via IMAP (reusing the same app-password credentials as SMTP), find
    recent messages with PDF attachments, and use Claude to extract bill data from each."""
    import imaplib
    import email as email_lib
    from email.header import decode_header
    from datetime import timedelta

    imap_host = IMAP_HOSTS.get(smtp_host, smtp_host.replace("smtp.", "imap."))

    try:
        mail = imaplib.IMAP4_SSL(imap_host, 993)
        mail.login(email_user, email_pass)
        mail.select("INBOX")
    except Exception as e:
        return {"success": False, "message": f"IMAP connection failed: {str(e)[:200]}"}

    try:
        since_date = (datetime.now() - timedelta(days=days_back)).strftime("%d-%b-%Y")
        status, msg_ids = mail.search(None, f'(SINCE {since_date})')
        if status != "OK":
            return {"success": False, "message": "IMAP search failed"}

        ids = msg_ids[0].split()
        ids = ids[-30:]  # cap at most recent 30 messages to keep this fast
        extracted_bills = []

        for msg_id in ids:
            status, msg_data = mail.fetch(msg_id, "(RFC822)")
            if status != "OK":
                continue
            raw = msg_data[0][1]
            msg = email_lib.message_from_bytes(raw)

            subject = ""
            if msg["Subject"]:
                parts = decode_header(msg["Subject"])
                subject = "".join([p[0].decode(p[1] or "utf-8") if isinstance(p[0], bytes) else p[0] for p in parts])

            sender = msg.get("From", "")

            # Look for PDF attachments
            for part in msg.walk():
                content_type = part.get_content_type()
                filename = part.get_filename()
                if content_type == "application/pdf" or (filename and filename.lower().endswith(".pdf")):
                    pdf_bytes = part.get_payload(decode=True)
                    if not pdf_bytes or len(pdf_bytes) < 100:
                        continue
                    extraction = extract_invoice_from_pdf(pdf_bytes, subject, sender)
                    if extraction:
                        extraction["source_subject"] = subject
                        extraction["source_sender"] = sender
                        extraction["source_filename"] = filename or "invoice.pdf"
                        extracted_bills.append(extraction)

        mail.close()
        mail.logout()
        return {"success": True, "bills": extracted_bills, "scanned_messages": len(ids)}
    except Exception as e:
        return {"success": False, "message": f"Email scan error: {str(e)[:200]}"}

def extract_invoice_from_pdf(pdf_bytes, subject, sender):
    """Use Claude's document understanding to pull structured bill data from a PDF attachment."""
    if not ANTHROPIC_API_KEY:
        return None
    try:
        pdf_b64 = base64.b64encode(pdf_bytes).decode()
        payload = {
            "model": "claude-haiku-4-5-20251001",
            "max_tokens": 500,
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": pdf_b64}},
                    {"type": "text", "text": f"""This PDF was attached to an email with subject "{subject}" from {sender}.

If this is an invoice or bill, extract the following as JSON only, no markdown:
{{"is_invoice": true, "vendor": "vendor/company name", "amount": 0.00, "invoice_number": "", "invoice_date": "YYYY-MM-DD or empty", "due_date": "YYYY-MM-DD or empty", "description": "brief description of goods/services"}}

If this is NOT an invoice or bill (e.g. a receipt confirmation, newsletter, or unrelated document), respond with exactly: {{"is_invoice": false}}"""}
                ]
            }]
        }
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01"
            }
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode())
        text = result.get("content", [{}])[0].get("text", "")
        text = text.strip().replace("```json", "").replace("```", "").strip()
        parsed = json.loads(text)
        if not parsed.get("is_invoice"):
            return None
        return parsed
    except Exception as e:
        print(f"  [Invoice Extraction] Error: {e}")
        return None


QBO_CLIENT_ID = os.environ.get("QBO_CLIENT_ID", "").strip()
QBO_CLIENT_SECRET = os.environ.get("QBO_CLIENT_SECRET", "").strip()
QBO_REDIRECT_URI = os.environ.get("QBO_REDIRECT_URI", "http://localhost:8090/qbo/callback").strip()
QBO_ENVIRONMENT = os.environ.get("QBO_ENVIRONMENT", "sandbox").strip()

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
GOOGLE_REDIRECT_URI = os.environ.get("GOOGLE_REDIRECT_URI", "http://localhost:8090/auth/google/callback").strip()

# System-level email (welcome emails, password resets) - separate from the per-user
# SMTP credentials configured in Settings for daily digest notifications. This needs
# its own dedicated sending account, since brand-new users haven't configured anything yet.
SYSTEM_SMTP_HOST = os.environ.get("SYSTEM_SMTP_HOST", "smtp.gmail.com").strip()
SYSTEM_SMTP_PORT = int(os.environ.get("SYSTEM_SMTP_PORT", "587"))
SYSTEM_SMTP_USER = os.environ.get("SYSTEM_SMTP_USER", "").strip()
SYSTEM_SMTP_PASS = os.environ.get("SYSTEM_SMTP_PASS", "").strip()
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:8090").strip()


def send_system_email(to_email, subject, html_body):
    """Sends a transactional email (welcome, password reset) from Shepherd's own
    account, not the recipient's. Silently no-ops with a log line if not configured,
    rather than raising - a missing welcome email shouldn't ever break signup."""
    if not SYSTEM_SMTP_USER or not SYSTEM_SMTP_PASS:
        print(f"  [Email] Skipped '{subject}' to {to_email} - SYSTEM_SMTP_USER/PASS not configured")
        return False
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"Shepherd <{SYSTEM_SMTP_USER}>"
        msg["To"] = to_email
        msg.attach(MIMEText(html_body, "html"))

        server = smtplib.SMTP(SYSTEM_SMTP_HOST, SYSTEM_SMTP_PORT)
        server.starttls()
        server.login(SYSTEM_SMTP_USER, SYSTEM_SMTP_PASS)
        server.sendmail(SYSTEM_SMTP_USER, to_email, msg.as_string())
        server.quit()
        print(f"  [Email] Sent '{subject}' to {to_email}")
        return True
    except Exception as e:
        print(f"  [Email] FAILED to send '{subject}' to {to_email}: {e}")
        return False


def send_welcome_email(to_email, name, org_name):
    first_name = (name or "").split(" ")[0] or "there"
    html = f"""
    <div style="font-family:-apple-system,sans-serif;max-width:480px;margin:0 auto;color:#0f172a">
      <h2 style="margin-bottom:4px">Welcome to Shepherd, {first_name}</h2>
      <p style="color:#475569;line-height:1.6">Your account for <strong>{org_name}</strong> is set up. Connect a wallet or bank account to get your first transactions classified.</p>
      <p style="color:#475569;line-height:1.6">This product is early, and your feedback genuinely shapes what gets built next. If anything is confusing, broken, or missing - just reply to this email and tell me directly.</p>
      <p style="color:#475569;line-height:1.6">Thanks for trying it out.</p>
    </div>
    """
    send_system_email(to_email, "Welcome to Shepherd", html)


def send_password_reset_email(to_email, reset_token):
    reset_link = f"{APP_BASE_URL}/?reset_token={reset_token}"
    html = f"""
    <div style="font-family:-apple-system,sans-serif;max-width:480px;margin:0 auto;color:#0f172a">
      <h2 style="margin-bottom:4px">Reset your Shepherd password</h2>
      <p style="color:#475569;line-height:1.6">Click the link below to set a new password. This link expires in 1 hour.</p>
      <p style="margin:24px 0"><a href="{reset_link}" style="background:#0f172a;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">Reset Password</a></p>
      <p style="color:#94a3b8;font-size:13px">If you didn't request this, you can safely ignore this email.</p>
    </div>
    """
    send_system_email(to_email, "Reset your Shepherd password", html)

qbo_tokens = {"access_token": None, "refresh_token": None, "realm_id": None, "expires_at": 0}

def qbo_base_url():
    if QBO_ENVIRONMENT == "production":
        return "https://quickbooks.api.intuit.com"
    return "https://sandbox-quickbooks.api.intuit.com"

def qbo_refresh_access_token():
    if not qbo_tokens["refresh_token"]:
        return False
    try:
        auth = base64.b64encode(f"{QBO_CLIENT_ID}:{QBO_CLIENT_SECRET}".encode()).decode()
        body = urllib.parse.urlencode({
            "grant_type": "refresh_token",
            "refresh_token": qbo_tokens["refresh_token"]
        }).encode()
        req = urllib.request.Request(
            "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer",
            data=body,
            headers={
                "Authorization": f"Basic {auth}",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json"
            }
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            tokens = json.loads(resp.read().decode())
        qbo_tokens["access_token"] = tokens["access_token"]
        qbo_tokens["refresh_token"] = tokens["refresh_token"]
        qbo_tokens["expires_at"] = time.time() + tokens.get("expires_in", 3600)
        return True
    except Exception as e:
        print(f"  [QBO] Token refresh error: {e}")
        return False

def qbo_get_accounts():
    """Fetch the chart of accounts from QBO to map names to IDs."""
    if not qbo_tokens["access_token"] or not qbo_tokens["realm_id"]:
        return {"success": False, "message": "QuickBooks not connected"}
    try:
        query = "SELECT Id, Name, AccountType, CurrentBalance FROM Account MAXRESULTS 1000"
        url = f"{qbo_base_url()}/v3/company/{qbo_tokens['realm_id']}/query?query={urllib.parse.quote(query)}&minorversion=65"
        req = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {qbo_tokens['access_token']}",
            "Accept": "application/json"
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read().decode())
        accounts = result.get("QueryResponse", {}).get("Account", [])
        return {"success": True, "accounts": [{"id": a["Id"], "name": a["Name"], "type": a.get("AccountType", ""), "balance": float(a.get("CurrentBalance", 0) or 0)} for a in accounts]}
    except urllib.error.HTTPError as e:
        error_body = e.read().decode() if e.fp else str(e)
        return {"success": False, "message": f"QBO Error {e.code}: {error_body[:200]}"}
    except Exception as e:
        return {"success": False, "message": str(e)[:200]}

def qbo_create_account(name, acct_type):
    """Create a new account in QBO's chart of accounts."""
    qbo_type_map = {
        "revenue": "Income",
        "expense": "Expense",
        "transfer": "Other Current Asset",
        "bank": "Bank"
    }
    payload = {
        "Name": name,
        "AccountType": qbo_type_map.get(acct_type, "Expense")
    }
    try:
        url = f"{qbo_base_url()}/v3/company/{qbo_tokens['realm_id']}/account?minorversion=65"
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {qbo_tokens['access_token']}",
            "Accept": "application/json"
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read().decode())
        return result.get("Account", {}).get("Id")
    except Exception as e:
        print(f"  [QBO] Could not create account '{name}': {e}")
        return None

def qbo_push_journal_entry(journals, memo="Shepherd Auto-Generated"):
    if not qbo_tokens["access_token"] or not qbo_tokens["realm_id"]:
        return {"success": False, "message": "QuickBooks not connected"}

    acct_result = qbo_get_accounts()
    if not acct_result.get("success"):
        return {"success": False, "message": "Could not fetch QBO accounts: " + acct_result.get("message", "")}

    qbo_accounts = acct_result["accounts"]
    name_to_id = {a["name"].lower(): a["id"] for a in qbo_accounts}

    lines = []
    created = []
    for j in journals:
        acct_name = j.get("account_name", "")
        acct_id = name_to_id.get(acct_name.lower())

        if not acct_id:
            # Auto-create the missing account in QBO so it matches Shepherd's chart exactly
            gl_type = j.get("gl_type", "expense")
            new_id = qbo_create_account(acct_name, gl_type)
            if new_id:
                acct_id = new_id
                name_to_id[acct_name.lower()] = new_id
                created.append(acct_name)

        if not acct_id:
            continue

        lines.append({
            "DetailType": "JournalEntryLineDetail",
            "Amount": round(j["amount"], 2),
            "Description": j.get("memo", memo),
            "JournalEntryLineDetail": {
                "PostingType": "Debit" if j["type"] == "debit" else "Credit",
                "AccountRef": {"value": acct_id}
            }
        })

    if not lines:
        return {"success": False, "message": "No accounts could be matched or created in QBO."}

    payload = {"Line": lines, "TxnDate": datetime.now().strftime("%Y-%m-%d"), "PrivateNote": memo}
    try:
        url = f"{qbo_base_url()}/v3/company/{qbo_tokens['realm_id']}/journalentry?minorversion=65"
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {qbo_tokens['access_token']}",
            "Accept": "application/json"
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read().decode())
        msg = "Journal entry created"
        if created:
            msg += f" ({len(created)} new account(s) created in QBO: {', '.join(set(created))})"
        return {"success": True, "id": result.get("JournalEntry", {}).get("Id"), "message": msg}
    except urllib.error.HTTPError as e:
        error_body = e.read().decode() if e.fp else str(e)
        return {"success": False, "message": f"QBO Error {e.code}: {error_body[:300]}"}
    except Exception as e:
        return {"success": False, "message": str(e)[:200]}

# ======================== HTTP SERVER ========================

# Configure AI provider: "claude" or "gemini"
AI_PROVIDER = os.environ.get("AI_PROVIDER", "claude").strip()  # toggle here
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()

def classify_transaction(tx_data, chart_of_accounts, prior_classifications, client_profile=None):
    """Use AI to suggest a GL classification for an unknown transaction."""
    # Build the prompt (same for both providers)
    prior_summary = ""
    if prior_classifications:
        for p in prior_classifications[:30]:
            prior_summary += f"- {p['counterparty'][:12]}...: {p['count']}x classified as \"{p['gl_code']}\" "
            prior_summary += f"({p['direction']}, avg ${p['avg_amount']:.2f}"
            if p.get('pattern'):
                prior_summary += f", {p['pattern']}"
            prior_summary += ")\n"

    # chart_of_accounts may be a flat list of code strings (legacy) or a list of
    # {code, description} objects — use the description when we have one, since
    # a one-line description of what an account is FOR is far higher signal than
    # the bare code+name alone.
    coa_lines = []
    for entry in chart_of_accounts:
        if isinstance(entry, dict):
            code = entry.get("code", "")
            desc = entry.get("description", "")
        else:
            code = entry
            desc = ""
        if code == "Unclassified":
            continue
        coa_lines.append(f"- {code}" + (f": {desc}" if desc else ""))
    coa_text = "\n".join(coa_lines)

    # Build client context
    biz_context = ""
    if client_profile:
        parts = []
        if client_profile.get('business_type'):
            parts.append(f"Business type: {', '.join(client_profile['business_type'])}")
        if client_profile.get('typical_transactions'):
            parts.append(f"Typical transactions: {', '.join(client_profile['typical_transactions'])}")
        if client_profile.get('notes'):
            parts.append(f"Additional context: {client_profile['notes']}")
        if client_profile.get('known_vendors'):
            vendor_lines = []
            for v in client_profile['known_vendors'][:20]:
                name = v.get('name', '')
                gl = v.get('gl_code', '')
                if name and gl:
                    vendor_lines.append(f"  - {name} -> {gl}")
            if vendor_lines:
                parts.append("Known recurring vendors/counterparties (use as reference patterns, including for similarly-named or similarly-behaving counterparties):\n" + "\n".join(vendor_lines))
        if parts:
            biz_context = "\n".join(parts)

    is_bank = tx_data.get('source') == 'bank'

    if is_bank:
        prompt = f"""You are an accounting transaction classifier for Shepherd, a continuous close accounting product covering both crypto and traditional bank activity.

Given a bank transaction and the customer's context, suggest the most likely GL code from their chart of accounts.

CHART OF ACCOUNTS:
{coa_text}

CLIENT CONTEXT:
{biz_context if biz_context else "No client context provided."}

PRIOR CLASSIFICATIONS BY THIS CUSTOMER:
{prior_summary if prior_summary else "No prior classifications yet."}

BANK TRANSACTION TO CLASSIFY:
- Direction: {tx_data.get('direction', 'unknown')}
- Amount: ${tx_data.get('amount', 0):,.2f}
- Merchant / Payee name: {tx_data.get('counterparty', 'unknown')}
- Date: {tx_data.get('block', 'unknown')}

Consider:
1. The merchant/payee name is often highly informative for bank transactions (e.g. "AWS", "Gusto Payroll", "Stripe" imply a category directly) — weigh this heavily.
2. Does the amount/timing match patterns in prior classifications?
3. Round recurring amounts often suggest payroll, rent, or subscriptions.
4. Inflows are typically revenue or transfers; outflows are typically expenses.

Respond with ONLY valid JSON, no markdown, no backticks:
{{"gl_code": "the full GL code string from the chart of accounts", "confidence": 0.0 to 1.0, "reasoning": "one sentence explanation"}}"""
    else:
        prompt = f"""You are a crypto accounting transaction classifier for Shepherd, a stablecoin accounting product.

Given a blockchain transaction and the customer's context, suggest the most likely GL code from their chart of accounts.

CHART OF ACCOUNTS:
{coa_text}

CLIENT CONTEXT:
{biz_context if biz_context else "No client context provided."}

PRIOR CLASSIFICATIONS BY THIS CUSTOMER:
{prior_summary if prior_summary else "No prior classifications yet."}

TRANSACTION TO CLASSIFY:
- Direction: {tx_data.get('direction', 'unknown')}
- Amount: ${tx_data.get('amount', 0):,.2f}
- Asset: {tx_data.get('asset', 'USDC')}
- Counterparty address: {tx_data.get('counterparty', 'unknown')}
- Chain: {tx_data.get('chain', 'unknown')}
- Block/Slot: {tx_data.get('block', 'unknown')}

Consider:
1. Does the amount/timing match patterns in prior classifications?
2. Is the counterparty similar to previously classified addresses?
3. Based on amount size and direction, what category is most likely?
4. Round amounts ($5000, $10000) often suggest payroll or planned payments
5. Small irregular amounts often suggest SaaS or operational costs
6. Inflows are typically revenue, outflows are typically expenses
7. If the asset is EURC, the amount is denominated in euros, not dollars — note this in your reasoning if relevant, since it affects how the transaction should be described

Respond with ONLY valid JSON, no markdown, no backticks:
{{"gl_code": "the full GL code string from the chart of accounts", "confidence": 0.0 to 1.0, "reasoning": "one sentence explanation"}}"""

    if AI_PROVIDER == "gemini":
        return _classify_gemini(prompt)
    else:
        return _classify_claude(prompt)


def _classify_claude(prompt):
    if not ANTHROPIC_API_KEY:
        return {"gl_code": None, "confidence": 0, "reasoning": "No ANTHROPIC_API_KEY set."}
    for attempt in range(3):
        try:
            payload = {
                "model": "claude-haiku-4-5-20251001",
                "max_tokens": 200,
                "messages": [{"role": "user", "content": prompt}]
            }
            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                }
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode())
            text = result.get("content", [{}])[0].get("text", "")
            text = text.strip().replace("```json", "").replace("```", "").strip()
            return json.loads(text)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            if attempt < 2:
                wait = (attempt + 1) * 2
                print(f"  [Claude] Timeout, retrying in {wait}s...")
                time.sleep(wait)
                continue
            print(f"  [Claude] Error: {e}")
            return {"gl_code": None, "confidence": 0, "reasoning": f"Connection error: {str(e)[:80]}"}
        except Exception as e:
            print(f"  [Claude] Error: {e}")
            return {"gl_code": None, "confidence": 0, "reasoning": f"Claude error: {str(e)[:100]}"}


def _classify_gemini(prompt):
    if not GEMINI_API_KEY:
        return {"gl_code": None, "confidence": 0, "reasoning": "No GEMINI_API_KEY set."}
    for attempt in range(3):
        try:
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"maxOutputTokens": 200, "temperature": 0.1}
            }
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={GEMINI_API_KEY}"
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read().decode())
            text = result.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
            text = text.strip().replace("```json", "").replace("```", "").strip()
            return json.loads(text)
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 2:
                wait = (attempt + 1) * 2
                print(f"  [Gemini] Rate limited, waiting {wait}s...")
                time.sleep(wait)
                continue
            print(f"  [Gemini] Error: {e}")
            return {"gl_code": None, "confidence": 0, "reasoning": f"Gemini error: {str(e)[:100]}"}
        except Exception as e:
            print(f"  [Gemini] Error: {e}")
            return {"gl_code": None, "confidence": 0, "reasoning": f"Gemini error: {str(e)[:100]}"}

def detect_chain(wallet, requested_chain=None):
    """If the caller specifies which chain (required for EVM chains, since Base/Ethereum/
    Polygon all share the same 0x address format), use that. Solana addresses are
    unambiguous by format alone. An EVM address with no chain specified is a real error,
    not something safe to guess — silently defaulting to Base would scan the wrong
    chain's contracts and produce quietly-wrong accounting data with no error at all."""
    if requested_chain and (requested_chain in EVM_CHAINS or requested_chain == "solana"):
        return requested_chain
    if wallet.startswith("0x") and len(wallet) == 42:
        if requested_chain:
            raise ValueError(f"Unknown chain '{requested_chain}' for an EVM address. Must be one of: {', '.join(EVM_CHAINS.keys())}")
        raise ValueError(
            "This address could be on Base, Ethereum, or Polygon — they share the same address format, "
            "so a chain must be specified explicitly. Please select the chain and try again."
        )
    return "solana"

# Global state for active scan
active_scan = {"running": False, "engine": None, "result": None, "error": None}

def run_scan(wallet, lookback, from_block=None, requested_chain=None):
    global active_scan
    try:
        chain = detect_chain(wallet, requested_chain)
        if chain in EVM_CHAINS:
            engine = EVMStablecoinLedger(wallet, chain_key=chain)
            active_scan["engine"] = engine
            to_block = engine.latest_block()
            if from_block is not None:
                scan_from = from_block
            else:
                scan_from = to_block - lookback
            chain_label = EVM_CHAINS[chain]["label"]
            token_list = ", ".join(engine.tokens.keys())
            print(f"  [{chain_label}] Scanning {wallet} for {token_list}, blocks {scan_from:,} -> {to_block:,}")
            report = engine.build_report(scan_from, to_block)
        else:
            engine = SolanaStablecoinLedger(wallet, tx_limit=lookback)
            active_scan["engine"] = engine
            print(f"  [Solana] Scanning {wallet} for {', '.join(SOLANA_TOKENS.keys())}, last {lookback} transactions")
            report = engine.build_report()

        active_scan["result"] = report
        active_scan["error"] = None
        print(f"  Done: {report['summary']['transfer_count']} stablecoin transfers found")
    except Exception as e:
        active_scan["error"] = str(e)
        active_scan["result"] = None
        print(f"  Error: {e}")
    finally:
        active_scan["running"] = False


class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/web/me":
            user = self._authed_web_user()
            self._send_json(200, {"logged_in": bool(user), "user": user})
            return

        if self.path == "/api/web/data":
            user = self._authed_web_user()
            if not user:
                print(f"  [Hydrate] 401 - no valid session cookie recognized (cookie header: {self.headers.get('Cookie', '<none>')[:80]})")
                self._send_json(401, {"error": "Not logged in"})
                return
            if not DB_AVAILABLE:
                self._send_json(503, {"error": "Persistence not configured on this server"})
                return
            org_id = user["org_id"]
            wallets = db_list_wallets(org_id)
            transactions = db_list_transactions(org_id, limit=10000)
            cp_mappings = db_get_counterparty_mappings(org_id)
            coa = db_get_chart_of_accounts(org_id)
            audit_log = db_list_audit_log(org_id)
            print(f"  [Hydrate] org_id={org_id}: {len(wallets)} wallets, {len(transactions)} transactions")
            self._send_json(200, {
                "success": True,
                "wallets": wallets,
                "transactions": transactions,
                "cp_mappings": cp_mappings,
                "chart_of_accounts": coa,
                "audit_log": audit_log,
            })
            return

        if self.path.startswith("/api/v1/wallets"):
            org = self._authed_org_any()
            if not org:
                self._send_json(401, {"error": "Invalid or missing API key"})
                return
            if not DB_AVAILABLE:
                self._send_json(503, {"error": "Persistence not configured on this server"})
                return
            qs = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(qs)
            end_user_id = params.get("end_user_id", [None])[0]
            wallets = db_list_wallets(org["id"], end_user_external_id=end_user_id)
            self._send_json(200, {"wallets": wallets})
            return

        if self.path.startswith("/api/v1/transactions"):
            org = self._authed_org_any()
            if not org:
                self._send_json(401, {"error": "Invalid or missing API key"})
                return
            if not DB_AVAILABLE:
                self._send_json(503, {"error": "Persistence not configured on this server"})
                return
            qs = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(qs)
            wallet_id = params.get("wallet_id", [None])[0]
            end_user_id = params.get("end_user_id", [None])[0]
            gl_code = params.get("gl_code", [None])[0]
            txs = db_list_transactions(org["id"], wallet_id=wallet_id, end_user_external_id=end_user_id, gl_code=gl_code)
            self._send_json(200, {"transactions": txs})
            return

        if self.path.startswith("/api/v1/financial-statements"):
            org = self._authed_org_any()
            if not org:
                self._send_json(401, {"error": "Invalid or missing API key"})
                return
            if not DB_AVAILABLE:
                self._send_json(503, {"error": "Persistence not configured on this server"})
                return
            qs = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(qs)
            wallet_id = params.get("wallet_id", [None])[0]
            end_user_id = params.get("end_user_id", [None])[0]
            stmt = db_financial_statements(org["id"], wallet_id=wallet_id, end_user_external_id=end_user_id)
            self._send_json(200, stmt)
            return

        if self.path.startswith("/api/fairvalue/prices"):
            import urllib.parse as _up
            qs = _up.urlparse(self.path).query
            params = _up.parse_qs(qs)
            symbols = params.get("symbols", [""])[0]  # comma-separated coingecko ids e.g. "ethereum,solana,bitcoin"
            if not symbols:
                symbols = "ethereum,solana,bitcoin"
            try:
                url = f"https://api.coingecko.com/api/v3/simple/price?ids={symbols}&vs_currencies=usd"
                req = urllib.request.Request(url, headers={"Accept": "application/json"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    prices = json.loads(resp.read().decode())
                result = {"success": True, "prices": prices, "as_of": datetime.now(timezone.utc).isoformat()}
            except Exception as e:
                result = {"success": False, "message": str(e)[:200]}
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
            return

        if self.path == "/api/plaid/status":
            connected = len(plaid_items) > 0
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"connected": connected, "item_count": len(plaid_items)}).encode())
            return

        if self.path.startswith("/api/reconcile/chain_balance"):
            query = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(query)
            address = params.get("address", [""])[0]
            chain = params.get("chain", [""])[0].lower()
            token_symbol = params.get("token", ["USDC"])[0].upper()
            try:
                if chain in EVM_CHAINS:
                    ledger = EVMStablecoinLedger(address, chain_key=chain)
                    balance = ledger.get_current_balance(address, token_symbol)
                elif chain == "solana":
                    ledger = SolanaStablecoinLedger(address)
                    balance = ledger.get_current_balance(address, token_symbol)
                else:
                    raise ValueError(f"Unknown chain: {chain}")
                result = {"success": True, "balance": balance, "address": address, "chain": chain, "token": token_symbol}
            except Exception as e:
                result = {"success": False, "message": str(e)[:200]}
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
            return

        if self.path == "/api/chains":
            chains_out = {}
            for key, cfg in EVM_CHAINS.items():
                chains_out[key] = {"label": cfg["label"], "tokens": list(cfg["tokens"].keys())}
            chains_out["solana"] = {"label": "Solana", "tokens": list(SOLANA_TOKENS.keys())}
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"chains": chains_out}).encode())
            return

        if self.path == "/api/billcom/status":
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"connected": bool(billcom_session["sessionId"])}).encode())
            return

        if self.path == "/api/qbo/accounts":
            result = qbo_get_accounts()
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
            return

        if self.path == "/api/qbo/status":
            connected = bool(qbo_tokens["access_token"] and qbo_tokens["realm_id"])
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"connected": connected, "realm_id": qbo_tokens.get("realm_id")}).encode())
            return

        if self.path == "/debug/env":
            debug_info = {
                "QBO_CLIENT_ID_set": bool(QBO_CLIENT_ID),
                "QBO_CLIENT_ID_len": len(QBO_CLIENT_ID) if QBO_CLIENT_ID else 0,
                "QBO_CLIENT_ID_preview": (QBO_CLIENT_ID[:6] + "..." + QBO_CLIENT_ID[-4:]) if len(QBO_CLIENT_ID) > 10 else QBO_CLIENT_ID,
                "QBO_CLIENT_SECRET_set": bool(QBO_CLIENT_SECRET),
                "QBO_CLIENT_SECRET_len": len(QBO_CLIENT_SECRET) if QBO_CLIENT_SECRET else 0,
                "QBO_CLIENT_SECRET_preview": (QBO_CLIENT_SECRET[:4] + "..." + QBO_CLIENT_SECRET[-4:]) if len(QBO_CLIENT_SECRET) > 8 else QBO_CLIENT_SECRET,
                "QBO_REDIRECT_URI": QBO_REDIRECT_URI,
                "ANTHROPIC_KEY_set": bool(ANTHROPIC_API_KEY),
                "GOOGLE_CLIENT_ID_set": bool(GOOGLE_CLIENT_ID),
                "GOOGLE_CLIENT_ID_preview": (GOOGLE_CLIENT_ID[:8] + "..." + GOOGLE_CLIENT_ID[-12:]) if len(GOOGLE_CLIENT_ID) > 20 else GOOGLE_CLIENT_ID,
                "GOOGLE_CLIENT_SECRET_set": bool(GOOGLE_CLIENT_SECRET),
                "GOOGLE_REDIRECT_URI": GOOGLE_REDIRECT_URI,
                "GOOGLE_REDIRECT_URI_note": "This EXACT string must appear character-for-character in Google Console under Authorized redirect URIs, including https:// and no trailing slash.",
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(debug_info, indent=2).encode())
            return

        if self.path.startswith("/auth/google") and not self.path.startswith("/auth/google/callback"):
            if not GOOGLE_CLIENT_ID:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<h3>Google sign-in isn't configured on this server yet.</h3><p>Set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and GOOGLE_REDIRECT_URI.</p>")
                return
            params = urllib.parse.urlencode({
                "client_id": GOOGLE_CLIENT_ID, "response_type": "code",
                "scope": "openid email profile",
                "redirect_uri": GOOGLE_REDIRECT_URI, "access_type": "online", "prompt": "select_account"
            })
            self.send_response(302)
            self.send_header("Location", f"https://accounts.google.com/o/oauth2/v2/auth?{params}")
            self.end_headers()
            return

        if self.path.startswith("/auth/google/callback"):
            query = urllib.parse.urlparse(self.path).query
            p = urllib.parse.parse_qs(query)
            code = p.get("code", [""])[0]
            if not code:
                self.send_response(400)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<h3>Google sign-in was cancelled or failed.</h3><p><a href='/'>Return to Shepherd</a></p>")
                return
            try:
                token_body = urllib.parse.urlencode({
                    "code": code, "client_id": GOOGLE_CLIENT_ID, "client_secret": GOOGLE_CLIENT_SECRET,
                    "redirect_uri": GOOGLE_REDIRECT_URI, "grant_type": "authorization_code"
                }).encode()
                token_req = urllib.request.Request("https://oauth2.googleapis.com/token", data=token_body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
                with urllib.request.urlopen(token_req, timeout=15) as resp:
                    tokens = json.loads(resp.read().decode())

                profile_req = urllib.request.Request("https://www.googleapis.com/oauth2/v2/userinfo",
                    headers={"Authorization": f"Bearer {tokens['access_token']}"})
                with urllib.request.urlopen(profile_req, timeout=15) as resp:
                    profile = json.loads(resp.read().decode())

                email = (profile.get("email") or "").strip().lower()
                name = profile.get("name") or email.split("@")[0]
                if not email:
                    raise ValueError("Google did not return an email address")
                if not DB_AVAILABLE:
                    raise RuntimeError("Persistence not configured on this server")

                result = find_or_create_user_by_google(email, name)
                if not result["success"]:
                    raise RuntimeError(result.get("message", "Could not create account"))

                self.send_response(302)
                self._cors()
                self.send_header("Set-Cookie", f"shepherd_session={result['token']}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax")
                self.send_header("Location", "/")
                self.end_headers()
                print(f"  [Google SSO] Signed in: {email}")
            except Exception as e:
                print(f"  [Google SSO] Error: {e}")
                self.send_response(500)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(f"<h3>Google sign-in failed</h3><pre>{str(e)[:300]}</pre><p><a href='/'>Return to Shepherd</a></p>".encode())
            return

        if self.path.startswith("/qbo/auth"):
            if not QBO_CLIENT_ID:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<h3>QBO_CLIENT_ID not set.</h3>")
                return
            params = urllib.parse.urlencode({
                "client_id": QBO_CLIENT_ID, "response_type": "code",
                "scope": "com.intuit.quickbooks.accounting",
                "redirect_uri": QBO_REDIRECT_URI, "state": "shepherd"
            })
            self.send_response(302)
            self.send_header("Location", f"https://appcenter.intuit.com/connect/oauth2?{params}")
            self.end_headers()
            return

        if self.path.startswith("/qbo/callback"):
            query = urllib.parse.urlparse(self.path).query
            p = urllib.parse.parse_qs(query)
            code = p.get("code", [""])[0]
            realm_id = p.get("realmId", [""])[0]
            if code and realm_id:
                try:
                    auth = base64.b64encode(f"{QBO_CLIENT_ID}:{QBO_CLIENT_SECRET}".encode()).decode()
                    body = urllib.parse.urlencode({"grant_type": "authorization_code", "code": code, "redirect_uri": QBO_REDIRECT_URI}).encode()
                    req = urllib.request.Request("https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer", data=body, headers={
                        "Authorization": f"Basic {auth}", "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"
                    })
                    with urllib.request.urlopen(req, timeout=15) as resp:
                        tokens = json.loads(resp.read().decode())
                    qbo_tokens["access_token"] = tokens["access_token"]
                    qbo_tokens["refresh_token"] = tokens["refresh_token"]
                    qbo_tokens["realm_id"] = realm_id
                    qbo_tokens["expires_at"] = time.time() + tokens.get("expires_in", 3600)
                    print(f"  [QBO] Connected! Realm ID: {realm_id}")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"<html><body><h2>QuickBooks Connected!</h2><p>You can close this tab.</p><script>window.opener&&window.opener.postMessage(\'qbo_connected\',\'*\');setTimeout(()=>window.close(),2000)</script></body></html>")
                except urllib.error.HTTPError as e:
                    error_body = e.read().decode() if e.fp else str(e)
                    print(f"  [QBO] Token exchange failed: {e.code} {error_body}")
                    self.send_response(500)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(f"<h3>OAuth Error {e.code}</h3><pre>{error_body}</pre><p>redirect_uri used: {QBO_REDIRECT_URI}</p>".encode())
                except Exception as e:
                    self.send_response(500)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(f"<h3>OAuth Error: {e}</h3>".encode())
            return

        if self.path == "/" or self.path == "/index.html":
            html_path = Path(__file__).parent / "stableledger_demo.html"
            if html_path.exists():
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(html_path.read_bytes())
            else:
                self.send_error(404, f"Put stableledger_demo.html next to this script")
            return

        if self.path == "/api/progress":
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            prog = {}
            if active_scan.get("engine"):
                prog = active_scan["engine"].progress
            self.wfile.write(json.dumps({
                "running": active_scan["running"],
                "progress": prog,
                "error": active_scan.get("error"),
            }).encode())
            return

        if self.path == "/api/result":
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            if active_scan.get("result"):
                self.wfile.write(json.dumps(active_scan["result"], ensure_ascii=True).encode())
            elif active_scan.get("error"):
                self.wfile.write(json.dumps({"error": active_scan["error"]}).encode())
            else:
                self.wfile.write(b'{"error":"No scan results yet"}')
            return

        self.send_error(404)

    def do_POST(self):
        if self.path == "/api/beta/signup":
            if not DB_AVAILABLE:
                self._send_json(503, {"error": "Signups aren't available right now — please try again shortly."})
                return
            body = self._read_json_body()
            name = (body.get("name") or "").strip()[:200]
            email = (body.get("email") or "").strip().lower()[:200]
            firm_name = (body.get("firm_name") or "").strip()[:200]
            message = (body.get("message") or "").strip()[:2000]
            if not email or "@" not in email:
                self._send_json(400, {"error": "A valid email is required."})
                return
            conn = db_conn()
            try:
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO beta_signups (name, email, firm_name, message) VALUES (%s, %s, %s, %s)",
                    (name, email, firm_name, message)
                )
                conn.commit()
                cur.close()
                print(f"  [Beta Signup] {email} ({firm_name or 'no firm given'})")
                self._send_json(200, {"success": True})
            except Exception as e:
                conn.rollback()
                print(f"  [Beta Signup] FAILED: {e}")
                self._send_json(500, {"error": "Something went wrong — please try again."})
            finally:
                db_release(conn)
            return

        if self.path == "/api/web/signup":
            if not DB_AVAILABLE:
                self._send_json(503, {"error": "Persistence not configured on this server"})
                return
            body = self._read_json_body()
            org_name = (body.get("org_name") or "").strip()
            email = (body.get("email") or "").strip().lower()
            password = body.get("password") or ""
            name = (body.get("name") or "").strip()
            if not org_name or not email or not password:
                self._send_json(400, {"error": "org_name, email, and password are required"})
                return
            if len(password) < 8:
                self._send_json(400, {"error": "Password must be at least 8 characters"})
                return
            result = signup_new_org(org_name, email, password, name)
            if not result["success"]:
                self._send_json(400, {"error": result["message"]})
                return
            send_welcome_email(email, name, org_name)
            self.send_response(201)
            self._cors()
            self.send_header("Set-Cookie", f"shepherd_session={result['token']}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax")
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "user": result["user"]}, default=str).encode())
            return

        if self.path == "/api/web/login":
            if not DB_AVAILABLE:
                self._send_json(503, {"error": "Persistence not configured on this server"})
                return
            body = self._read_json_body()
            email = (body.get("email") or "").strip().lower()
            password = body.get("password") or ""
            result = login_user(email, password)
            if not result["success"]:
                self._send_json(401, {"error": result["message"]})
                return
            self.send_response(200)
            self._cors()
            self.send_header("Set-Cookie", f"shepherd_session={result['token']}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax")
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "user": result["user"]}, default=str).encode())
            return

        if self.path == "/api/web/password-reset/request":
            if not DB_AVAILABLE:
                self._send_json(503, {"error": "Persistence not configured on this server"})
                return
            body = self._read_json_body()
            email = (body.get("email") or "").strip().lower()
            if not email:
                self._send_json(400, {"error": "Email is required"})
                return

            conn = db_conn()
            try:
                cur = conn.cursor()
                cur.execute("SELECT id FROM users WHERE email = %s", (email,))
                row = cur.fetchone()
                if row:
                    user_id = row[0]
                    token = secrets.token_urlsafe(32)
                    cur.execute(
                        "INSERT INTO password_reset_tokens (token, user_id, expires_at) VALUES (%s, %s, now() + interval '1 hour')",
                        (token, user_id)
                    )
                    conn.commit()
                    send_password_reset_email(email, token)
                    print(f"  [Password Reset] Requested for {email}")
                cur.close()
            except Exception as e:
                conn.rollback()
                print(f"  [Password Reset] Error: {e}")
            finally:
                db_release(conn)

            # Always return success regardless of whether the email exists - this avoids
            # leaking which emails are registered to anyone probing the endpoint.
            self._send_json(200, {"success": True, "message": "If an account exists for that email, a reset link has been sent."})
            return

        if self.path == "/api/web/password-reset/confirm":
            if not DB_AVAILABLE:
                self._send_json(503, {"error": "Persistence not configured on this server"})
                return
            body = self._read_json_body()
            token = (body.get("token") or "").strip()
            new_password = body.get("password") or ""
            if not token or not new_password:
                self._send_json(400, {"error": "token and password are required"})
                return
            if len(new_password) < 8:
                self._send_json(400, {"error": "Password must be at least 8 characters"})
                return

            conn = db_conn()
            try:
                cur = conn.cursor()
                cur.execute(
                    "SELECT user_id FROM password_reset_tokens WHERE token = %s AND used = false AND expires_at > now()",
                    (token,)
                )
                row = cur.fetchone()
                if not row:
                    cur.close()
                    self._send_json(400, {"error": "This reset link is invalid or has expired. Please request a new one."})
                    return
                user_id = row[0]
                pw_hash, salt = hash_password(new_password)
                cur.execute("UPDATE users SET password_hash = %s, salt = %s WHERE id = %s", (pw_hash, salt, user_id))
                cur.execute("UPDATE password_reset_tokens SET used = true WHERE token = %s", (token,))
                conn.commit()
                cur.close()
                print(f"  [Password Reset] Completed for user_id={user_id}")
                self._send_json(200, {"success": True})
            except Exception as e:
                conn.rollback()
                print(f"  [Password Reset] Confirm error: {e}")
                self._send_json(500, {"error": "Something went wrong. Please try again."})
            finally:
                db_release(conn)
            return

        if self.path == "/api/web/logout":
            self.send_response(200)
            self._cors()
            self.send_header("Set-Cookie", "shepherd_session=; Path=/; Max-Age=0")
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True}).encode())
            return

        if self.path == "/api/web/wallets/save":
            user = self._authed_web_user()
            if not user:
                self._send_json(401, {"error": "Not logged in"})
                return
            if not DB_AVAILABLE:
                self._send_json(503, {"error": "Persistence not configured on this server"})
                return
            body = self._read_json_body()
            address = (body.get("address") or "").strip()
            chain = (body.get("chain") or "").strip().lower()
            name = body.get("name") or address
            lookback = int(body.get("lookback") or 1000)
            txs = body.get("transactions") or []
            if not address or not chain:
                self._send_json(400, {"error": "address and chain are required"})
                return
            wallet_id = db_save_wallet_v1(user["org_id"], None, address, name, chain, lookback)
            if not wallet_id:
                self._send_json(500, {"error": "Could not save wallet"})
                return
            saved_count = db_save_transactions_v1(user["org_id"], wallet_id, txs)
            db_save_audit_entry_v1(user["org_id"], None, "account", "Wallet connected",
                                    f"{name} ({chain}) — {saved_count} transactions")
            self._send_json(201, {"success": True, "wallet_id": wallet_id, "transactions_saved": saved_count})
            return

        if self.path == "/api/web/transactions/sync":
            # Persist new transactions found on a rescan of an already-saved wallet.
            user = self._authed_web_user()
            if not user:
                self._send_json(401, {"error": "Not logged in"})
                return
            if not DB_AVAILABLE:
                self._send_json(503, {"error": "Persistence not configured on this server"})
                return
            body = self._read_json_body()
            wallet_id = body.get("wallet_id")
            txs = body.get("transactions") or []
            last_block = body.get("last_block")
            if not wallet_id:
                self._send_json(400, {"error": "wallet_id is required"})
                return
            saved_count = db_save_transactions_v1(user["org_id"], wallet_id, txs)
            if last_block is not None:
                conn = db_conn()
                try:
                    cur = conn.cursor()
                    cur.execute("UPDATE wallets SET last_block = %s, last_scan_time = %s WHERE id = %s AND org_id = %s",
                                (last_block, datetime.now(timezone.utc).isoformat(), wallet_id, user["org_id"]))
                    conn.commit()
                    cur.close()
                except Exception as e:
                    conn.rollback()
                    print(f"  [DB] update wallet last_block error: {e}")
                finally:
                    db_release(conn)
            self._send_json(200, {"success": True, "transactions_saved": saved_count})
            return

        if self.path == "/api/web/transactions/classify":
            user = self._authed_web_user()
            if not user:
                self._send_json(401, {"error": "Not logged in"})
                return
            if not DB_AVAILABLE:
                self._send_json(503, {"error": "Persistence not configured on this server"})
                return
            body = self._read_json_body()
            wallet_id = body.get("wallet_id")
            tx_hash = body.get("tx_hash")
            gl_code = body.get("gl_code")
            counterparty = body.get("counterparty")
            if not wallet_id or not tx_hash or not gl_code:
                self._send_json(400, {"error": "wallet_id, tx_hash, and gl_code are required"})
                return
            conn = db_conn()
            try:
                cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                cur.execute("SELECT id FROM transactions WHERE org_id = %s AND wallet_id = %s AND tx_hash = %s",
                            (user["org_id"], wallet_id, tx_hash))
                row = cur.fetchone()
                cur.close()
            finally:
                db_release(conn)
            if not row:
                self._send_json(404, {"error": "Transaction not found"})
                return
            ok = db_classify_transaction_v1(user["org_id"], row["id"], gl_code)
            if counterparty and gl_code != "Unclassified":
                db_save_counterparty_mapping(user["org_id"], None, counterparty, gl_code)
            self._send_json(200, {"success": ok})
            return

        if self.path == "/api/web/chart_of_accounts/save":
            user = self._authed_web_user()
            if not user:
                self._send_json(401, {"error": "Not logged in"})
                return
            if not DB_AVAILABLE:
                self._send_json(503, {"error": "Persistence not configured on this server"})
                return
            body = self._read_json_body()
            code = body.get("code")
            name = body.get("name")
            account_type = body.get("account_type", "expense")
            description = body.get("description", "")
            if not code or not name:
                self._send_json(400, {"error": "code and name are required"})
                return
            ok = db_save_chart_of_accounts_entry(user["org_id"], code, name, account_type, description)
            self._send_json(200 if ok else 500, {"success": ok})
            return

        if self.path == "/api/web/audit_log":
            user = self._authed_web_user()
            if user and DB_AVAILABLE:
                body = self._read_json_body()
                db_save_audit_entry_v1(user["org_id"], None, body.get("type", ""), body.get("action", ""), body.get("detail", ""))
            self._send_json(200, {"success": bool(user)})
            return

        if self.path == "/api/v1/wallets":
            org = self._authed_org_any()
            if not org:
                self._send_json(401, {"error": "Invalid or missing API key"})
                return
            if not DB_AVAILABLE:
                self._send_json(503, {"error": "Persistence not configured on this server"})
                return
            body = self._read_json_body()
            address = (body.get("address") or "").strip()
            chain = (body.get("chain") or "").strip().lower()
            end_user_external_id = body.get("end_user_id")
            name = body.get("name") or address
            lookback = int(body.get("lookback_blocks", 2000))

            if not address:
                self._send_json(400, {"error": "address is required"})
                return
            if chain not in EVM_CHAINS and chain != "solana":
                self._send_json(400, {"error": f"chain must be one of: {', '.join(list(EVM_CHAINS.keys()) + ['solana'])}"})
                return

            end_user_id = None
            if end_user_external_id:
                end_user_id = db_get_or_create_end_user(org["id"], end_user_external_id, body.get("end_user_name"))

            wallet_id = db_save_wallet_v1(org["id"], end_user_id, address, name, chain, lookback)
            if not wallet_id:
                self._send_json(500, {"error": "Could not save wallet"})
                return

            # Run the scan synchronously so the caller gets classified data back in one round trip.
            # For very large lookback windows this can be slow — v2 should offer an async/webhook mode.
            try:
                if chain in EVM_CHAINS:
                    engine = EVMStablecoinLedger(address, chain_key=chain)
                    to_block = engine.latest_block()
                    from_block = to_block - lookback
                    report = engine.build_report(from_block, to_block)
                else:
                    engine = SolanaStablecoinLedger(address, tx_limit=lookback)
                    report = engine.build_report()
            except Exception as e:
                self._send_json(502, {"error": f"Scan failed: {str(e)[:300]}", "wallet_id": wallet_id})
                return

            txs_to_save = [{
                "hash": j["tx_hash"], "block": j.get("block_number"), "dir": j["direction"],
                "amount": j["amount"], "cp": j["counterparty"], "gas": j.get("gas_usd", 0),
                "asset": j.get("asset", "USDC"), "source": "blockchain"
            } for j in report.get("journals", [])]
            saved_count = db_save_transactions_v1(org["id"], wallet_id, txs_to_save)

            chain_label = EVM_CHAINS[chain]["label"] if chain in EVM_CHAINS else "Solana"
            classify_result = auto_classify_new_transactions(org["id"], wallet_id, end_user_id, chain_label)

            db_save_audit_entry_v1(org["id"], end_user_id, "account", "Wallet connected via API",
                                    f"{address} ({chain}) — {saved_count} transactions found, {classify_result['classified']} auto-classified")

            self._send_json(201, {
                "wallet_id": wallet_id,
                "address": address,
                "chain": chain,
                "end_user_id": end_user_external_id,
                "transactions_found": len(txs_to_save),
                "transactions_saved": saved_count,
                "transactions_classified": classify_result["classified"],
                "transactions_needing_review": classify_result["reviewed"] - classify_result["classified"],
                "summary": report.get("summary", {})
            })
            return

        if self.path.startswith("/api/v1/wallets/") and self.path.endswith("/scan"):
            org = self._authed_org_any()
            if not org:
                self._send_json(401, {"error": "Invalid or missing API key"})
                return
            if not DB_AVAILABLE:
                self._send_json(503, {"error": "Persistence not configured on this server"})
                return
            try:
                wallet_id = int(self.path.split("/")[4])
            except (IndexError, ValueError):
                self._send_json(400, {"error": "Invalid wallet id"})
                return
            wallet = db_get_wallet(org["id"], wallet_id)
            if not wallet:
                self._send_json(404, {"error": "Wallet not found"})
                return

            chain = wallet["chain"]
            address = wallet["address"]
            lookback = wallet.get("lookback") or 2000
            try:
                if chain in EVM_CHAINS:
                    engine = EVMStablecoinLedger(address, chain_key=chain)
                    to_block = engine.latest_block()
                    from_block = (wallet["last_block"] + 1) if wallet.get("last_block") else (to_block - lookback)
                    report = engine.build_report(from_block, to_block)
                else:
                    engine = SolanaStablecoinLedger(address, tx_limit=lookback)
                    report = engine.build_report()
            except Exception as e:
                self._send_json(502, {"error": f"Scan failed: {str(e)[:300]}"})
                return

            txs_to_save = [{
                "hash": j["tx_hash"], "block": j.get("block_number"), "dir": j["direction"],
                "amount": j["amount"], "cp": j["counterparty"], "gas": j.get("gas_usd", 0),
                "asset": j.get("asset", "USDC"), "source": "blockchain"
            } for j in report.get("journals", [])]
            saved_count = db_save_transactions_v1(org["id"], wallet_id, txs_to_save)
            chain_label = EVM_CHAINS[chain]["label"] if chain in EVM_CHAINS else "Solana"
            classify_result = auto_classify_new_transactions(org["id"], wallet_id, wallet.get("end_user_id"), chain_label)

            db_save_audit_entry_v1(org["id"], wallet.get("end_user_id"), "scan", "Wallet rescanned via API",
                                    f"{address} — {saved_count} new transactions, {classify_result['classified']} auto-classified")

            self._send_json(200, {
                "wallet_id": wallet_id,
                "transactions_found": len(txs_to_save),
                "transactions_saved": saved_count,
                "transactions_classified": classify_result["classified"],
                "transactions_needing_review": classify_result["reviewed"] - classify_result["classified"],
                "summary": report.get("summary", {})
            })
            return

        if self.path.startswith("/api/v1/transactions/") and self.path.endswith("/classify"):
            org = self._authed_org_any()
            if not org:
                self._send_json(401, {"error": "Invalid or missing API key"})
                return
            if not DB_AVAILABLE:
                self._send_json(503, {"error": "Persistence not configured on this server"})
                return
            try:
                transaction_id = int(self.path.split("/")[4])
            except (IndexError, ValueError):
                self._send_json(400, {"error": "Invalid transaction id"})
                return
            body = self._read_json_body()
            gl_code = body.get("gl_code")
            if not gl_code:
                self._send_json(400, {"error": "gl_code is required"})
                return
            ok = db_classify_transaction_v1(org["id"], transaction_id, gl_code)
            if not ok:
                self._send_json(404, {"error": "Transaction not found"})
                return
            self._send_json(200, {"success": True})
            return

        if self.path == "/api/classify":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode()) if length else {}

            tx_data = body.get("transaction", {})
            coa = body.get("chart_of_accounts", [])
            prior = body.get("prior_classifications", [])
            profile = body.get("client_profile", None)

            print(f"  [{AI_PROVIDER.title()}] Classifying: ${tx_data.get('amount',0):,.2f} {tx_data.get('direction','?')} to {tx_data.get('counterparty','?')[:16]}...")
            suggestion = classify_transaction(tx_data, coa, prior, profile)
            print(f"  [{AI_PROVIDER.title()}] Suggested: {suggestion.get('gl_code','?')} ({suggestion.get('confidence',0):.0%})")

            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(suggestion, ensure_ascii=True).encode())
            return

        if self.path == "/api/send-email":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode()) if length else {}
            try:
                import smtplib
                from email.mime.text import MIMEText
                from email.mime.multipart import MIMEMultipart

                smtp_host = body.get("smtp_host", "smtp.gmail.com")
                smtp_port = int(body.get("smtp_port", 587))
                smtp_user = body.get("smtp_user", "")
                smtp_pass = body.get("smtp_pass", "")
                to_email = body.get("to", "")
                subject = body.get("subject", "Shepherd Daily Update")
                html_body = body.get("body", "")

                msg = MIMEMultipart("alternative")
                msg["Subject"] = subject
                msg["From"] = smtp_user
                msg["To"] = to_email
                msg.attach(MIMEText(html_body, "html"))

                server = smtplib.SMTP(smtp_host, smtp_port)
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.sendmail(smtp_user, to_email, msg.as_string())
                server.quit()

                print(f"  [Email] Sent to {to_email}")
                result = {"success": True, "message": f"Email sent to {to_email}"}
            except Exception as e:
                print(f"  [Email] Error: {e}")
                result = {"success": False, "message": str(e)[:200]}

            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
            return

        if self.path == "/api/send-slack":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode()) if length else {}
            try:
                webhook_url = body.get("webhook_url", "")
                text = body.get("text", "")
                blocks = body.get("blocks")

                payload = {"text": text}
                if blocks:
                    payload["blocks"] = blocks

                req = urllib.request.Request(
                    webhook_url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"}
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    resp.read()

                print(f"  [Slack] Message sent")
                result = {"success": True, "message": "Slack message sent"}
            except Exception as e:
                print(f"  [Slack] Error: {e}")
                result = {"success": False, "message": str(e)[:200]}

            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
            return


        if self.path == "/api/plaid/create_link_token":
            result = plaid_create_link_token()
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
            return

        if self.path == "/api/plaid/exchange_token":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode()) if length else {}
            public_token = body.get("public_token", "")
            result = plaid_exchange_public_token(public_token)
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
            return

        if self.path == "/api/plaid/accounts":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode()) if length else {}
            item_id = body.get("item_id", "")
            item = plaid_items.get(item_id)
            if not item:
                result = {"success": False, "message": "Unknown item_id"}
            else:
                result = plaid_get_accounts(item["access_token"])
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
            return

        if self.path == "/api/plaid/transactions":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode()) if length else {}
            item_id = body.get("item_id", "")
            cursor = body.get("cursor")
            item = plaid_items.get(item_id)
            if not item:
                result = {"success": False, "message": "Unknown item_id"}
            else:
                result = plaid_sync_transactions(item["access_token"], cursor)
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
            return

        if self.path == "/api/billcom/connect":
            result = billcom_login()
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
            return

        if self.path == "/api/billcom/bills":
            result = billcom_get_bills()
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
            return

        if self.path == "/api/email/scan_invoices":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode()) if length else {}
            smtp_host = body.get("smtp_host", "smtp.gmail.com")
            email_user = body.get("email_user", "")
            email_pass = body.get("email_pass", "")
            days_back = int(body.get("days_back", 14))
            print(f"  [Email Invoices] Scanning inbox for {email_user} (last {days_back} days)...")
            result = scan_email_invoices(smtp_host, email_user, email_pass, days_back)
            if result.get("success"):
                print(f"  [Email Invoices] Found {len(result.get('bills', []))} invoice(s) in {result.get('scanned_messages', 0)} messages")
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
            return

        if self.path == "/api/qbo/push":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode()) if length else {}
            if time.time() > qbo_tokens.get("expires_at", 0) - 300:
                qbo_refresh_access_token()
            result = qbo_push_journal_entry(body.get("journals", []))
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
            return

        if self.path == "/api/scan":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode()) if length else {}
            wallet = body.get("wallet", "").strip()
            lookback = int(body.get("lookback_blocks", 1000))
            requested_chain = (body.get("chain") or "").strip().lower() or None

            is_evm = wallet.startswith("0x") and len(wallet) == 42
            is_solana = not wallet.startswith("0x") and 32 <= len(wallet) <= 44
            if not is_evm and not is_solana:
                self.send_response(400)
                self._cors()
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Invalid wallet address"}).encode())
                return
            if requested_chain and requested_chain not in EVM_CHAINS and requested_chain != "solana":
                self.send_response(400)
                self._cors()
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": f"Unknown chain: {requested_chain}"}).encode())
                return

            if active_scan["running"]:
                self.send_response(409)
                self._cors()
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Scan already running"}).encode())
                return

            active_scan["running"] = True
            active_scan["result"] = None
            active_scan["error"] = None
            from_block = body.get("from_block")
            print(f"\n[SCAN] Starting for {wallet}, chain={requested_chain or 'auto'}, lookback={lookback}" + (f", from_block={from_block}" if from_block else ""))
            threading.Thread(target=run_scan, args=(wallet, lookback, from_block, requested_chain), daemon=True).start()

            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "started"}).encode())
            return

        self.send_error(404)

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def _authed_org(self):
        """Extract and validate the API key from Authorization: Bearer <key>."""
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        api_key = auth[7:].strip()
        return get_org_from_api_key(api_key)

    def _get_session_token(self):
        cookie_header = self.headers.get("Cookie", "")
        for part in cookie_header.split(";"):
            part = part.strip()
            if part.startswith("shepherd_session="):
                return part.split("=", 1)[1]
        return None

    def _authed_web_user(self):
        """Web app auth via session cookie, separate from the API-key auth above,
        but resolving to the same underlying organization/wallet/transaction data."""
        return get_user_from_session(self._get_session_token())

    def _authed_org_any(self):
        """Accept EITHER an API key (Bearer token, for programmatic access) OR a
        session cookie (for the web app). Both resolve to the same org-scoped data,
        so every /api/v1/* endpoint can serve both the web UI and API customers."""
        org = self._authed_org()
        if org:
            return org
        user = self._authed_web_user()
        if user:
            return {"id": user["org_id"], "name": user["org_name"]}
        return None

    def _send_json(self, code, payload):
        body = json.dumps(payload, default=str).encode()
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length).decode()) if length else {}

    def log_message(self, format, *args):
        # Quiet down request logging, keep our own prints
        pass


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "create-org":
        if len(sys.argv) < 4:
            print("Usage: python3 stableledger_server.py create-org \"Org Name\" \"contact@email.com\"")
            sys.exit(1)
        if not DB_AVAILABLE:
            print("DATABASE_URL is not set or the database isn't reachable — cannot provision an org without persistence configured.")
            sys.exit(1)
        result = create_organization(sys.argv[2], sys.argv[3])
        if result["success"]:
            print(f"\nOrganization created: {sys.argv[2]} (id={result['org_id']})")
            print(f"\nAPI key (shown once — store it securely, it cannot be retrieved again):\n")
            print(f"  {result['api_key']}\n")
        else:
            print(f"Error: {result['message']}")
        sys.exit(0)

    port = int(os.environ.get("PORT", 8090))
    print(f"Shepherd server starting on http://localhost:{port}")
    print(f"Open that URL in your browser.")
    if AI_PROVIDER == "gemini" and GEMINI_API_KEY:
        print(f"AI classification: Gemini Flash (enabled)")
    elif AI_PROVIDER == "claude" and ANTHROPIC_API_KEY:
        print(f"AI classification: Claude Haiku (enabled)")
    else:
        print(f"AI classification: disabled (set ANTHROPIC_API_KEY or GEMINI_API_KEY)")
        print(f"  Current provider: {AI_PROVIDER}")
    if DB_AVAILABLE:
        print(f"Persistence + API: enabled (multi-tenant, /api/v1/*)")
    else:
        print(f"Persistence + API: disabled (set DATABASE_URL to enable)")
    print()
    server = HTTPServer(("0.0.0.0", port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()
