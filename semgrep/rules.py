# Semgrep rule fixtures: annotated lines mark where each detector must and must not fire.
# Detector test cases only, not runnable application code.
import hashlib
import requests
from flask import request, render_template_string


def sql(cur, name, uid):
    # ruleid: formatted-sql-string
    cur.execute("SELECT * FROM t WHERE name='%s'" % name)
    # ruleid: formatted-sql-string
    cur.execute(f"SELECT * FROM t WHERE id={uid}")
    # ok: formatted-sql-string
    cur.execute("SELECT * FROM t WHERE id=?", (uid,))


def xss():
    # ruleid: jinja-unescaped-output
    return render_template_string("Hello " + request.args.get("name", ""))


def ssrf():
    # ruleid: ssrf-request-from-user-input
    return requests.get(request.args.get("url"))


def weak(password):
    # ruleid: weak-password-hash
    return hashlib.md5(password).hexdigest()


def ok_hash(data):
    # ok: weak-password-hash
    return hashlib.sha256(data).hexdigest()


def run(app):
    # ruleid: flask-debug-enabled
    app.run(debug=True)
