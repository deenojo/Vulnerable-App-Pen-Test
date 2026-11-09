"""Ledgerly: a minimal invoicing app that serves as the *fixed* reference for the remediated
OWASP Top 10 findings in findings/. Every route here demonstrates a control, not a vulnerability.

Run locally only:  FLASK_SECRET=dev python -m flask --app app.ledgerly run
"""
from __future__ import annotations

import os
import sqlite3
from functools import wraps

from flask import (Flask, abort, g, jsonify, redirect, request, session, url_for)
from markupsafe import escape

from .security import hash_password, verify_password, validate_outbound_url

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user', bio TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS invoices (
  id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL, customer TEXT NOT NULL,
  amount_cents INTEGER NOT NULL);
"""

# Logos may only be fetched from these vendor hosts (F04 SSRF allowlist).
ALLOWED_LOGO_HOSTS = {"cdn.example-invoicing.com"}


def _db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


def seed(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    if conn.execute("SELECT 1 FROM users").fetchone():
        return
    users = [("alice", "alice-pw", "user", "Alice in accounting"),
             ("bob", "bob-pw", "user", "Bob from sales"),
             ("admin", "admin-pw", "admin", "Administrator")]
    for name, pw, role, bio in users:
        conn.execute("INSERT INTO users (username, password_hash, role, bio) VALUES (?, ?, ?, ?)",
                     (name, hash_password(pw), role, bio))
    conn.executemany("INSERT INTO invoices (owner_id, customer, amount_cents) VALUES (?, ?, ?)",
                     [(1, "Acme Corp", 120000), (1, "Globex", 45000),
                      (2, "Initech", 990000), (3, "Internal", 100)])
    conn.commit()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            abort(401)
        return view(*args, **kwargs)
    return wrapped


def create_app(database: str = ":memory:") -> Flask:
    app = Flask(__name__)
    # F06 Security Misconfiguration: secret from the environment, debug never on in the factory.
    app.config.update(
        SECRET_KEY=os.environ.get("FLASK_SECRET", "change-me-in-prod"),
        DATABASE=database,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=True,
    )

    global current_app
    current_app = app

    if database == ":memory:":
        app.config["_shared"] = sqlite3.connect(":memory:", check_same_thread=False)
        app.config["_shared"].row_factory = sqlite3.Row
        seed(app.config["_shared"])
    else:
        conn = sqlite3.connect(database)
        conn.row_factory = sqlite3.Row
        seed(conn)
        conn.close()

    def db() -> sqlite3.Connection:
        if "_shared" in app.config:
            return app.config["_shared"]
        return _db()

    @app.after_request
    def set_security_headers(resp):  # F06 + F03 (CSP limits XSS impact)
        resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers.pop("Server", None)
        return resp

    @app.post("/login")
    def login():
        row = db().execute("SELECT id, password_hash FROM users WHERE username = ?",
                           (request.form.get("username", ""),)).fetchone()
        # Constant-ish response: verify even when the user is missing, to avoid user enumeration.
        stored = row["password_hash"] if row else "$2b$12$" + "x" * 53
        if row and verify_password(request.form.get("password", ""), stored):
            session.clear()
            session["user_id"] = row["id"]
            return jsonify(ok=True)
        abort(401)

    @app.get("/invoices/search")
    @login_required
    def search_invoices():
        # F01 Injection: parameterized query; the term is bound, never concatenated.
        term = request.args.get("q", "")
        rows = db().execute(
            "SELECT id, customer, amount_cents FROM invoices WHERE owner_id = ? AND customer LIKE ?",
            (session["user_id"], f"%{term}%")).fetchall()
        return jsonify([dict(r) for r in rows])

    @app.get("/invoices/<int:invoice_id>")
    @login_required
    def get_invoice(invoice_id: int):
        # F02 Broken Access Control / IDOR: enforce object-level ownership on every access.
        row = db().execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
        if row is None:
            abort(404)
        user = db().execute("SELECT role FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        if row["owner_id"] != session["user_id"] and user["role"] != "admin":
            abort(403)  # not your invoice
        return jsonify(dict(row))

    @app.get("/profile/<int:user_id>")
    @login_required
    def profile(user_id: int):
        # F03 XSS: the bio is escaped before it reaches HTML. Autoescape + explicit escape().
        row = db().execute("SELECT username, bio FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            abort(404)
        html = f"<h1>{escape(row['username'])}</h1><p>{escape(row['bio'])}</p>"
        return html, 200, {"Content-Type": "text/html; charset=utf-8"}

    @app.post("/profile/logo")
    @login_required
    def set_logo():
        # F04 SSRF: the user-supplied URL is validated against an allowlist and public-IP check.
        try:
            safe = validate_outbound_url(request.form.get("url", ""), ALLOWED_LOGO_HOSTS)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(accepted=safe)  # a real app would fetch `safe` here, after validation

    return app


current_app: Flask  # set in create_app
