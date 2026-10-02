"""QuantumSafe VPN Cloud - Flask web app (ML-KEM-1024 + ML-DSA-65, AES-256-GCM).
Run locally:  pip install -r requirements.txt  &&  python app.py   ->  http://127.0.0.1:5000
Deploy:       see README.md (Render). Set env var SECRET_KEY to a long random string.
Billing is a DEMO: choosing a plan just switches it; no money is charged."""
import hashlib, io, json, os, secrets, sqlite3, struct, time
from datetime import datetime
from functools import wraps
from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   send_file, session, url_for)
from jinja2 import DictLoader
from werkzeug.security import check_password_hash, generate_password_hash
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.kem import ml_kem_1024 as KEM
from pqcrypto.sign import ml_dsa_65 as DSA

SECRET = os.environ.get("SECRET_KEY", "dev-only-change-me")
DB_PATH = os.environ.get("DB_PATH", "quantumsafe.db")
MAGIC = b"PQSAFE03"
PLANS = {
    "free": {"name": "Free", "price": "₹0", "desc": "Key generation + live PQC handshake demo", "rank": 0},
    "pro": {"name": "Pro", "price": "₹499/mo", "desc": "Everything in Free + file encrypt / decrypt", "rank": 1},
    "enterprise": {"name": "Enterprise", "price": "₹1999/mo", "desc": "Everything in Pro + key bundle export + audit log", "rank": 2},
}

app = Flask(__name__)
app.secret_key = SECRET
app.config.update(MAX_CONTENT_LENGTH=10 * 1024 * 1024, SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=bool(os.environ.get("RENDER")))
VAULT = AESGCM(hashlib.sha256(SECRET.encode()).digest())

# ---------------------------------------------------------------- database --
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()

with sqlite3.connect(DB_PATH) as c:
    c.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, "
              "pw TEXT NOT NULL, plan TEXT NOT NULL DEFAULT 'free', keys BLOB, created TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, uid INTEGER, ts TEXT, event TEXT)")

def audit(uid, event):
    db().execute("INSERT INTO audit(uid,ts,event) VALUES(?,?,?)", (uid, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), event))
    db().commit()

def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    return db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

def get_keys(user):
    if not user or not user["keys"]:
        return None
    blob = user["keys"]
    d = json.loads(VAULT.decrypt(blob[:12], blob[12:], None))
    return {k: bytes.fromhex(v) for k, v in d.items()}

def put_keys(uid, keys):
    n = os.urandom(12)
    blob = n + VAULT.encrypt(n, json.dumps({k: bytes(v).hex() for k, v in keys.items()}).encode(), None)
    db().execute("UPDATE users SET keys=? WHERE id=?", (blob, uid))
    db().commit()

def fingerprint(pk):
    h = hashlib.sha256(pk).hexdigest()[:32]
    return ":".join(h[i:i + 4] for i in range(0, 32, 4))

# ------------------------------------------------------------- crypto core --
def derive(secret, ctx, label):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"QuantumSafeVPN|" + label + b"|" + ctx).derive(secret)

def protect(data, kem_pk, dsa_sk):
    ct, secret = KEM.encaps(kem_pk)
    key = derive(secret, hashlib.sha256(ct).digest(), b"file")
    nonce = os.urandom(12)
    pkg = MAGIC + struct.pack(">I", len(ct)) + ct + nonce + AESGCM(key).encrypt(nonce, data, MAGIC)
    sig = DSA.sign(dsa_sk, pkg)
    return pkg + sig + struct.pack(">I", len(sig))

def recover(blob, kem_sk, dsa_pk):
    if len(blob) < len(MAGIC) + 8:
        raise ValueError("file too short")
    (sl,) = struct.unpack(">I", blob[-4:])
    if sl == 0 or sl > len(blob) - 4:
        raise ValueError("corrupt file")
    sig, pkg = blob[-4 - sl:-4], blob[:-4 - sl]
    try:
        DSA.verify(dsa_pk, pkg, sig)
    except Exception:
        raise ValueError("signature check failed (wrong account or tampered file)")
    if pkg[:len(MAGIC)] != MAGIC:
        raise ValueError("not a .pqsafe file")
    o = len(MAGIC)
    (cl,) = struct.unpack(">I", pkg[o:o + 4])
    ct = pkg[o + 4:o + 4 + cl]
    o += 4 + cl
    key = derive(KEM.decaps(kem_sk, ct), hashlib.sha256(ct).digest(), b"file")
    try:
        return AESGCM(key).decrypt(pkg[o:o + 12], pkg[o + 12:], MAGIC)
    except InvalidTag:
        raise ValueError("decryption failed")

def handshake_demo(k):
    log, t0 = [], time.perf_counter()
    def step(m): log.append(f"[{(time.perf_counter() - t0) * 1000:8.2f} ms] {m}")
    tag = b"QSVPN-HANDSHAKE-v3"
    sig = DSA.sign(k["dsa_sk"], tag + k["kem_pk"])
    step(f"SERVER  signed its ML-KEM-1024 public key with ML-DSA-65 ({len(sig)} B signature)")
    DSA.verify(k["dsa_pk"], tag + k["kem_pk"], sig)
    step("CLIENT  verified the server signature  ✔ (identity authenticated)")
    ct, ss_c = KEM.encaps(k["kem_pk"])
    step(f"CLIENT  encapsulated a shared secret (ciphertext {len(ct)} B)")
    ss_s = KEM.decaps(k["kem_sk"], ct)
    step(f"SERVER  decapsulated it - secrets match: {ss_c == ss_s}  ✔")
    key = derive(ss_c, hashlib.sha256(k["kem_pk"] + ct).digest(), b"session")
    step("BOTH    derived a 256-bit AES-GCM session key with HKDF-SHA256")
    msg, n = b"Hello from the quantum-safe tunnel", os.urandom(12)
    enc = AESGCM(key).encrypt(n, msg, None)
    step(f"CLIENT  encrypted {len(msg)} B -> {len(enc)} B: {enc[:16].hex()}…")
    step(f"SERVER  decrypted: {AESGCM(key).decrypt(n, enc, None).decode()!r}  ✔")
    bad = bytearray(enc); bad[0] ^= 1
    try:
        AESGCM(key).decrypt(n, bytes(bad), None)
    except InvalidTag:
        step("ATTACK  flipped one bit in transit -> rejected by authentication  ✔")
    return log

# ------------------------------------------------------------------- views --
@app.before_request
def csrf():
    session.setdefault("t", secrets.token_hex(16))
    if request.method == "POST" and not secrets.compare_digest(request.form.get("t", ""), session["t"]):
        abort(400)

@app.context_processor
def ctx():
    return {"user": current_user(), "plans": PLANS}

def login_required(f):
    @wraps(f)
    def w(*a, **kw):
        if not session.get("uid"):
            return redirect(url_for("login"))
        return f(*a, **kw)
    return w

def needs(plan):
    def deco(f):
        @wraps(f)
        def w(*a, **kw):
            u = current_user()
            if PLANS[u["plan"]]["rank"] < PLANS[plan]["rank"]:
                flash(f"This feature needs the {PLANS[plan]['name']} plan.", "err")
                return redirect(url_for("dashboard"))
            return f(*a, **kw)
        return w
    return deco

def dash(log=None):
    u = current_user()
    k = get_keys(u)
    rows = db().execute("SELECT ts,event FROM audit WHERE uid=? ORDER BY id DESC LIMIT 15", (u["id"],)).fetchall()
    return render_template("dashboard.html", fp=fingerprint(k["dsa_pk"]) if k else None, log=log, rows=rows,
                           rank=PLANS[u["plan"]]["rank"])

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/healthz")
def healthz():
    return "ok"

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email, pw = request.form.get("email", "").strip().lower(), request.form.get("password", "")
        if "@" not in email or len(pw) < 8:
            flash("Enter a valid email and a password of at least 8 characters.", "err")
        else:
            try:
                cur = db().execute("INSERT INTO users(email,pw,created) VALUES(?,?,?)",
                                   (email, generate_password_hash(pw), datetime.utcnow().isoformat()))
                db().commit()
                session["uid"] = cur.lastrowid
                audit(cur.lastrowid, "Account created")
                return redirect(url_for("dashboard"))
            except sqlite3.IntegrityError:
                flash("That email is already registered.", "err")
    return render_template("auth.html", title="Create account", btn="Sign up")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = db().execute("SELECT * FROM users WHERE email=?", (request.form.get("email", "").strip().lower(),)).fetchone()
        if u and check_password_hash(u["pw"], request.form.get("password", "")):
            session.clear()
            session["uid"] = u["id"]
            audit(u["id"], "Signed in")
            return redirect(url_for("dashboard"))
        flash("Wrong email or password.", "err")
    return render_template("auth.html", title="Sign in", btn="Sign in")

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    return dash()

@app.route("/subscribe/<plan>", methods=["POST"])
@login_required
def subscribe(plan):
    if plan not in PLANS:
        abort(404)
    u = current_user()
    db().execute("UPDATE users SET plan=? WHERE id=?", (plan, u["id"]))
    db().commit()
    audit(u["id"], f"Plan changed to {PLANS[plan]['name']} (demo billing)")
    flash(f"Plan switched to {PLANS[plan]['name']} (demo billing - no payment taken).", "ok")
    return redirect(url_for("dashboard"))

@app.route("/keys/generate", methods=["POST"])
@login_required
def gen_keys():
    u = current_user()
    kp, ks = KEM.keygen()
    dp, ds = DSA.keygen()
    put_keys(u["id"], {"kem_pk": kp, "kem_sk": ks, "dsa_pk": dp, "dsa_sk": ds})
    audit(u["id"], "Generated ML-KEM-1024 + ML-DSA-65 keys")
    flash("New post-quantum keys generated.", "ok")
    return redirect(url_for("dashboard"))

@app.route("/handshake", methods=["POST"])
@login_required
def handshake():
    u = current_user()
    k = get_keys(u)
    if not k:
        flash("Generate your keys first.", "err")
        return redirect(url_for("dashboard"))
    audit(u["id"], "Ran PQC handshake demo")
    return dash(handshake_demo(k))

@app.route("/encrypt", methods=["POST"])
@login_required
@needs("pro")
def encrypt():
    u, k, f = current_user(), None, request.files.get("file")
    k = get_keys(u)
    if not k or not f or not f.filename:
        flash("Generate keys and choose a file first.", "err")
        return redirect(url_for("dashboard"))
    blob = protect(f.read(), k["kem_pk"], k["dsa_sk"])
    audit(u["id"], f"Encrypted file {os.path.basename(f.filename)}")
    return send_file(io.BytesIO(blob), as_attachment=True, download_name=os.path.basename(f.filename) + ".pqsafe")

@app.route("/decrypt", methods=["POST"])
@login_required
@needs("pro")
def decrypt():
    u, f = current_user(), request.files.get("file")
    k = get_keys(u)
    if not k or not f or not f.filename.endswith(".pqsafe"):
        flash("Choose a .pqsafe file that was protected with your account's keys.", "err")
        return redirect(url_for("dashboard"))
    try:
        data = recover(f.read(), k["kem_sk"], k["dsa_pk"])
    except ValueError as e:
        flash(f"Could not decrypt: {e}", "err")
        return redirect(url_for("dashboard"))
    audit(u["id"], f"Decrypted file {os.path.basename(f.filename)}")
    return send_file(io.BytesIO(data), as_attachment=True, download_name=os.path.basename(f.filename)[:-7])

@app.route("/bundle")
@login_required
@needs("enterprise")
def bundle():
    k = get_keys(current_user())
    if not k:
        flash("Generate your keys first.", "err")
        return redirect(url_for("dashboard"))
    b = {"kem_pk": k["kem_pk"].hex(), "dsa_pk": k["dsa_pk"].hex(), "fingerprint": fingerprint(k["dsa_pk"]),
         "config": {"kem": "ML-KEM-1024", "sig": "ML-DSA-65", "standard": "FIPS 203/204"}}
    return send_file(io.BytesIO(json.dumps(b, indent=2).encode()), as_attachment=True,
                     download_name="enterprise_pqc_bundle.json", mimetype="application/json")

# --------------------------------------------------------------- templates --
CSS = """*{box-sizing:border-box}body{margin:0;font-family:system-ui,Segoe UI,Arial;background:#0a0a1a;color:#e8e8f5}
a{color:#00ff88}nav{display:flex;gap:16px;align-items:center;padding:14px 28px;background:#12122b;border-bottom:1px solid #26264a}
nav b{color:#00ff88;font-size:18px;margin-right:auto}main{max-width:1100px;margin:0 auto;padding:24px}
.card{background:#16163a;border:1px solid #2a2a55;border-radius:12px;padding:20px;margin:12px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px}
button,.btn{background:#00c46a;color:#04120a;border:0;border-radius:8px;padding:10px 16px;font-weight:700;cursor:pointer;text-decoration:none;display:inline-block}
button.alt{background:#2a2a55;color:#e8e8f5}input{width:100%;padding:10px;margin:6px 0 12px;border-radius:8px;border:1px solid #3a3a70;background:#0d0d24;color:#fff}
pre{background:#000a11;color:#00ff88;padding:14px;border-radius:8px;overflow-x:auto;font-size:13px}code{color:#7fe}
.badge{background:#ffd54a;color:#222;border-radius:20px;padding:2px 12px;font-size:14px}.ok{color:#00ff88}
.flash{padding:10px 14px;border-radius:8px;margin:10px 0}.flash.ok{background:#0b3a22}.flash.err{background:#4a1620;color:#ffb3c0}
table{width:100%;border-collapse:collapse}td{padding:6px;border-bottom:1px solid #26264a;font-size:14px}.hero{text-align:center;padding:40px 0}
.hero h1{font-size:40px;color:#00ff88;margin:0}.price{font-size:26px;font-weight:800}"""

TEMPLATES = {
"base.html": """<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>QuantumSafe VPN Cloud</title><style>""" + CSS + """</style></head><body>
<nav><b>🛡 QUANTUMSAFE VPN CLOUD</b>
{% if user %}<a href="/dashboard">Dashboard</a><span>{{ user.email }}</span>
<form method=post action="/logout" style="margin:0"><input type=hidden name=t value="{{ session.t }}"><button class=alt>Log out</button></form>
{% else %}<a href="/login">Sign in</a><a class=btn href="/register">Get started</a>{% endif %}</nav>
<main>{% for c,m in get_flashed_messages(with_categories=true) %}<div class="flash {{ c }}">{{ m }}</div>{% endfor %}
{% block body %}{% endblock %}</main></body></html>""",
"pricing.html": """<div class=grid>{% for key,p in plans.items() %}<div class=card><h3>{{ p.name }}</h3>
<div class=price>{{ p.price }}</div><p>{{ p.desc }}</p>
{% if not user %}<a class=btn href="/register">Start</a>
{% elif user.plan==key %}<button class=alt disabled>Current plan</button>
{% else %}<form method=post action="/subscribe/{{ key }}"><input type=hidden name=t value="{{ session.t }}"><button>Choose {{ p.name }}</button></form>{% endif %}
</div>{% endfor %}</div><p style="opacity:.6">Demo billing: choosing a plan only switches it, no payment is taken.</p>""",
"index.html": """{% extends "base.html" %}{% block body %}<div class=hero><h1>Quantum-safe security, in your browser</h1>
<p>Post-quantum key exchange (ML-KEM-1024, FIPS 203), signatures (ML-DSA-65, FIPS 204) and AES-256-GCM encryption.</p>
<a class=btn href="/register">Create free account</a></div>{% include "pricing.html" %}{% endblock %}""",
"auth.html": """{% extends "base.html" %}{% block body %}<div class=card style="max-width:420px;margin:30px auto"><h2>{{ title }}</h2>
<form method=post><input type=hidden name=t value="{{ session.t }}">Email<input name=email type=email required>
Password<input name=password type=password required minlength=8><button>{{ btn }}</button></form></div>{% endblock %}""",
"dashboard.html": """{% extends "base.html" %}{% block body %}
<h1>Dashboard <span class=badge>{{ plans[user.plan].name }}</span></h1><div class=grid>
<div class=card><h3>1 · Your PQC keys</h3>{% if fp %}<p class=ok>Active · ID <code>{{ fp }}</code></p>{% else %}<p>No keys yet.</p>{% endif %}
<form method=post action="/keys/generate" {% if fp %}onsubmit="return confirm('Old keys will be replaced; files protected with them can no longer be opened. Continue?')"{% endif %}>
<input type=hidden name=t value="{{ session.t }}"><button>{{ 'Regenerate' if fp else 'Generate' }} keys</button></form></div>
<div class=card><h3>2 · Live PQC handshake</h3><p>Runs ML-KEM + ML-DSA + AES-GCM step by step.</p>
<form method=post action="/handshake"><input type=hidden name=t value="{{ session.t }}"><button>Run handshake</button></form></div>
<div class=card><h3>3 · File protection</h3>{% if rank>=1 %}
<form method=post action="/encrypt" enctype=multipart/form-data><input type=hidden name=t value="{{ session.t }}"><input type=file name=file required><button>Encrypt &amp; download</button></form><br>
<form method=post action="/decrypt" enctype=multipart/form-data><input type=hidden name=t value="{{ session.t }}"><input type=file name=file accept=".pqsafe" required><button class=alt>Decrypt .pqsafe</button></form>
{% else %}<p>🔒 Upgrade to Pro to encrypt and decrypt files (max 10 MB).</p>{% endif %}</div>
<div class=card><h3>4 · Key bundle &amp; audit log</h3>{% if rank>=2 %}<a class=btn href="/bundle">Download public key bundle</a>
<table>{% for r in rows %}<tr><td>{{ r.ts }}</td><td>{{ r.event }}</td></tr>{% endfor %}</table>
{% else %}<p>🔒 Upgrade to Enterprise for the key bundle and audit log.</p>{% endif %}</div></div>
{% if log %}<div class=card><h3>Handshake result</h3><pre>{{ log|join("\\n") }}</pre></div>{% endif %}
<h2>Plans</h2>{% include "pricing.html" %}{% endblock %}""",
}
app.jinja_env.loader = DictLoader(TEMPLATES)

if __name__ == "__main__":
    app.run(debug=True)
