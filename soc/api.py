"""SOC response API: signed user dialogue, Keycloak response actions (with verification),
analyst dashboard. The DECISIONS are taken by n8n; this service only executes and records."""
import os, time, json, hmac, hashlib, base64, sqlite3, threading, uuid, smtplib, logging, html
from email.message import EmailMessage
import requests
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from common import KC, N8N_BASE

logging.basicConfig(level=logging.INFO, format="%(asctime)s api %(message)s")
log = logging.getLogger("api")

DB = os.getenv("API_DB", "/data/api.db")
SECRET = os.getenv("SIGNING_SECRET", "change-me-lab-secret").encode()
PUBLIC_URL = os.getenv("SOC_PUBLIC_URL", "http://localhost:8000")
SMTP_HOST, SMTP_PORT = os.getenv("SMTP_HOST", "mailpit"), int(os.getenv("SMTP_PORT", "1025"))
CHALLENGE_TTL = int(os.getenv("CHALLENGE_TTL", "120"))   # seconds the user has to answer
ANALYST_TTL = int(os.getenv("ANALYST_TTL", "180"))       # seconds the analyst has to decide
REQUIRED_ACTIONS = ["UPDATE_PASSWORD", "CONFIGURE_TOTP"]

kc = KC()
app = FastAPI(title="SOC response API")
lock = threading.Lock()


def conn():
    c = sqlite3.connect(DB, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def init():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    c = conn()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS alerts(alert_id TEXT PRIMARY KEY, ts REAL, type TEXT, username TEXT, ip TEXT,
      geo TEXT, score INT, level TEXT, decision TEXT, status TEXT, email TEXT, privileged INT, user_id TEXT,
      reasons TEXT, data TEXT, analyst_deadline REAL, action TEXT, detected_at REAL, event_time REAL);
    CREATE TABLE IF NOT EXISTS timeline(id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT, ts REAL, event TEXT, detail TEXT);
    CREATE TABLE IF NOT EXISTS challenges(token_id TEXT PRIMARY KEY, alert_id TEXT, expires REAL, status TEXT);
    CREATE TABLE IF NOT EXISTS undo(alert_id TEXT PRIMARY KEY, user_id TEXT, before TEXT);
    """)
    c.commit()
    c.close()


def q(sql, args=(), one=False, write=False):
    with lock:
        c = conn()
        cur = c.execute(sql, args)
        if write:
            c.commit()
            c.close()
            return None
        rows = cur.fetchall()
        c.close()
        return (rows[0] if rows else None) if one else rows


def tl(alert_id, event, detail=""):
    q("INSERT INTO timeline(alert_id, ts, event, detail) VALUES(?,?,?,?)", (alert_id, time.time(), event, detail), write=True)


def store_alert(a, status):
    q("""INSERT OR REPLACE INTO alerts(alert_id, ts, type, username, ip, geo, score, level, decision, status, email,
         privileged, user_id, reasons, data, analyst_deadline, action, detected_at, event_time)
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,NULL,?,?)""",
      (a["alert_id"], time.time(), a.get("type"), a.get("user"), a.get("ip"), a.get("geo"), a.get("score"),
       a.get("level"), a.get("decision"), status, a.get("email"), int(bool(a.get("privileged"))), a.get("user_id"),
       json.dumps(a.get("reasons", [])), json.dumps(a), a.get("detected_at"), a.get("event_time")), write=True)
    tl(a["alert_id"], f"ALERT {a.get('type')}",
       f"score={a.get('score')} ({a.get('level')}) decision={a.get('decision')} | " + "; ".join(a.get("reasons", [])))


def set_status(aid, status, **extra):
    q("UPDATE alerts SET status=? WHERE alert_id=?", (status, aid), write=True)
    for k, v in extra.items():
        q(f"UPDATE alerts SET {k}=? WHERE alert_id=?", (v, aid), write=True)


def post_n8n(path, payload, aid):
    try:
        requests.post(f"{N8N_BASE}/webhook/{path}", json=payload, timeout=10).raise_for_status()
    except Exception as e:
        tl(aid, "ERROR n8n unreachable", str(e))
        log.error("n8n: %s", e)


# ---------- signed tokens ----------
def b64(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")
def unb64(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_token(token_id, expires):
    p = b64(json.dumps({"c": token_id, "e": expires}).encode())
    return p + "." + b64(hmac.new(SECRET, p.encode(), hashlib.sha256).digest())


def read_token(tok):
    """Returns challenge row if signature valid, not expired and still pending, else None."""
    try:
        p, s = tok.split(".")
        if not hmac.compare_digest(s, b64(hmac.new(SECRET, p.encode(), hashlib.sha256).digest())):
            return None
        d = json.loads(unb64(p))
        if d["e"] < time.time():
            return None
        row = q("SELECT * FROM challenges WHERE token_id=?", (d["c"],), one=True)
        return row if row and row["status"] == "pending" else None
    except Exception:
        return None


# ---------- email dialogue ----------
def send_challenge_mail(a, token):
    link = f"{PUBLIC_URL}/u/{token}"
    when = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(a.get("event_time") or time.time()))
    what = {"impossible_travel": "a sign-in from a location too far from your previous one",
            "brute_force": "many failed sign-in attempts on your account",
            "success_after_failures": "a successful sign-in right after many failed attempts"}.get(a["type"], "unusual activity")
    m = EmailMessage()
    m["Subject"] = "University security: was this you?"
    m["From"], m["To"] = "security@univ.test", a["email"]
    m.set_content(f"We detected {what}.\nTime: {when}\nIP: {a['ip']} ({a.get('geo')})\n\n"
                  f"Please answer within {CHALLENGE_TTL//60 if CHALLENGE_TTL>=60 else CHALLENGE_TTL} "
                  f"{'minutes' if CHALLENGE_TTL>=60 else 'seconds'}:\n{link}\n\n"
                  "If you do not answer, your sessions will be closed as a precaution.")
    m.add_alternative(f"""<p>We detected <b>{html.escape(what)}</b>.</p>
<p>Time: {when}<br>IP: {html.escape(a['ip'])} ({html.escape(str(a.get('geo')))})</p>
<p><a href="{link}" style="background:#2563eb;color:#fff;padding:10px 16px;border-radius:6px;text-decoration:none">Answer now</a></p>
<p style="color:#666">No answer within the delay = your sessions are closed as a precaution.</p>""", subtype="html")
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
        s.send_message(m)


# ---------- n8n -> API ----------
@app.post("/api/log")
async def api_log(request: Request):
    a = await request.json()
    store_alert(a, "logged")
    tl(a["alert_id"], "LOGGED ONLY", "score below action threshold, no user impact")
    return {"ok": True}


@app.post("/api/challenge")
async def api_challenge(request: Request):
    a = await request.json()
    store_alert(a, "awaiting_user")
    tid, exp = uuid.uuid4().hex, time.time() + CHALLENGE_TTL
    q("INSERT INTO challenges VALUES(?,?,?, 'pending')", (tid, a["alert_id"], exp), write=True)
    try:
        send_challenge_mail(a, make_token(tid, exp))
        tl(a["alert_id"], "QUESTION SENT TO USER", f"email to {a['email']}, expires in {CHALLENGE_TTL}s")
    except Exception as e:
        tl(a["alert_id"], "ERROR email", str(e))
    return {"ok": True}


@app.post("/api/case")
async def api_case(request: Request):
    a = await request.json()
    store_alert(a, "awaiting_analyst")
    set_status(a["alert_id"], "awaiting_analyst", analyst_deadline=time.time() + ANALYST_TTL)
    tl(a["alert_id"], "ANALYST CASE OPENED", f"decision needed within {ANALYST_TTL}s, else soft containment only")
    return {"ok": True}


@app.post("/api/timeline")
async def api_timeline(request: Request):
    d = await request.json()
    tl(d["alert_id"], d.get("event", "note"), d.get("detail", ""))
    if d.get("event") == "verification_failed":
        set_status(d["alert_id"], "needs_attention")
    return {"ok": True}


@app.post("/api/respond")
async def api_respond(request: Request):
    d = await request.json()
    aid, action = d["alert_id"], d["action"]
    row = q("SELECT * FROM alerts WHERE alert_id=?", (aid,), one=True)
    if not row:
        return JSONResponse({"verified": False, "error": "unknown alert"}, 404)
    uid, detail, verified = row["user_id"], "", True
    try:
        if action == "close":
            detail = "no change on the account"
            set_status(aid, "closed", action="close")
        elif not uid:
            detail = "no account to act on"
            set_status(aid, "closed", action=action)
        else:
            u = kc.user(uid)
            if action in ("hard", "lock") and not q("SELECT 1 FROM undo WHERE alert_id=?", (aid,), one=True):
                q("INSERT INTO undo VALUES(?,?,?)", (aid, uid, json.dumps(
                    {"enabled": u.get("enabled", True), "requiredActions": u.get("requiredActions", [])})), write=True)
            if action in ("hard", "lock"):
                if action == "hard":
                    u["requiredActions"] = sorted(set(u.get("requiredActions", [])) | set(REQUIRED_ACTIONS))
                else:
                    u["enabled"] = False
                kc.update_user(uid, u)
            kc.logout(uid)
            # verification of the REAL effect
            u2, sess = kc.user(uid), kc.sessions(uid)
            verified = len(sess) == 0
            if action == "hard":
                verified = verified and set(REQUIRED_ACTIONS) <= set(u2.get("requiredActions", []))
            if action == "lock":
                verified = verified and u2.get("enabled") is False
            detail = f"sessions_left={len(sess)} requiredActions={u2.get('requiredActions')} enabled={u2.get('enabled')}"
            set_status(aid, f"contained_{action}" if verified else "verification_failed", action=action)
    except Exception as e:
        verified, detail = False, f"error: {e}"
        set_status(aid, "verification_failed", action=action)
    tl(aid, f"RESPONSE {action.upper()} ({d.get('reason','')})", f"verified={verified} | {detail}")
    return {"alert_id": aid, "action": action, "verified": verified, "detail": detail}


# ---------- user dialogue pages ----------
def page(body, title="Security check"):
    return HTMLResponse(f"""<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>{title}</title><style>body{{font-family:system-ui;max-width:640px;margin:40px auto;padding:0 16px;color:#111}}
button{{font-size:16px;padding:10px 18px;border:0;border-radius:6px;color:#fff;cursor:pointer;margin-right:8px}}
.y{{background:#16a34a}}.n{{background:#dc2626}}table{{border-collapse:collapse;width:100%}}
td,th{{border-bottom:1px solid #ddd;padding:6px;text-align:left;font-size:13px;vertical-align:top}}</style>{body}""")


@app.get("/u/{token}")
def user_page(token: str):
    ch = read_token(token)
    if not ch:
        return page("<h2>Link invalid, expired or already used</h2><p>Nothing more to do.</p>")
    a = q("SELECT * FROM alerts WHERE alert_id=?", (ch["alert_id"],), one=True)
    return page(f"""<h2>Was this you?</h2><p>Sign-in from <b>{html.escape(a['ip'])}</b> ({html.escape(a['geo'] or '')}).</p>
<form method=post action="/u/{token}/yes" style="display:inline"><button class=y>Yes, it was me</button></form>
<form method=post action="/u/{token}/no" style="display:inline"><button class=n>No, it was not me</button></form>""")


@app.post("/u/{token}/{answer}")
def user_answer(token: str, answer: str):
    ch = read_token(token)
    if not ch or answer not in ("yes", "no"):
        return page("<h2>Link invalid, expired or already used</h2>")
    q("UPDATE challenges SET status='answered' WHERE token_id=?", (ch["token_id"],), write=True)
    aid = ch["alert_id"]
    ans = "confirmed" if answer == "yes" else "denied"
    set_status(aid, "processing")
    tl(aid, f"USER ANSWERED {ans.upper()}", "signed link, single use")
    post_n8n("idr-decision", {"source": "user", "alert_id": aid, "answer": ans}, aid)
    if ans == "confirmed":
        return page("<h2>Thank you</h2><p>Activity confirmed. No action taken.</p>")
    return page("<h2>Thank you, we are securing your account</h2><p>Your sessions are closed. You will have to change your password and set up MFA at next sign-in.</p>")


# ---------- analyst dashboard ----------
@app.post("/analyst/{aid}/{decision}")
def analyst(aid: str, decision: str):
    row = q("SELECT * FROM alerts WHERE alert_id=?", (aid,), one=True)
    if row and row["status"] == "awaiting_analyst" and decision in ("approve_lock", "approve_hard", "dismiss"):
        set_status(aid, "processing", analyst_deadline=None)
        tl(aid, f"ANALYST DECISION {decision.upper()}")
        post_n8n("idr-decision", {"source": "analyst", "alert_id": aid, "decision": decision}, aid)
    return RedirectResponse("/", status_code=303)


@app.post("/revert/{aid}")
def revert(aid: str):
    u = q("SELECT * FROM undo WHERE alert_id=?", (aid,), one=True)
    if u:
        b = json.loads(u["before"])
        rep = kc.user(u["user_id"])
        rep["enabled"], rep["requiredActions"] = b["enabled"], b["requiredActions"]
        kc.update_user(u["user_id"], rep)
        set_status(aid, "reverted")
        tl(aid, "REVERTED BY ANALYST", f"restored {b}")
    return RedirectResponse("/", status_code=303)


@app.get("/api/alerts")
def api_alerts():
    out = []
    for r in q("SELECT * FROM alerts ORDER BY ts"):
        d = dict(r)
        d["reasons"] = json.loads(d["reasons"] or "[]")
        d.pop("data", None)
        d["timeline"] = [dict(t) for t in q("SELECT ts, event, detail FROM timeline WHERE alert_id=? ORDER BY id", (r["alert_id"],))]
        out.append(d)
    return out


BADGE = {"logged": "#6b7280", "awaiting_user": "#d97706", "awaiting_analyst": "#dc2626", "processing": "#2563eb",
         "closed": "#16a34a", "contained_soft": "#7c3aed", "contained_hard": "#7c3aed", "contained_lock": "#7c3aed",
         "reverted": "#0891b2", "verification_failed": "#000", "needs_attention": "#000"}


@app.get("/", response_class=HTMLResponse)
def dashboard():
    rows = []
    for r in reversed(q("SELECT * FROM alerts ORDER BY ts")):
        t = "<br>".join(f"<small>{time.strftime('%H:%M:%S', time.localtime(x['ts']))} <b>{html.escape(x['event'])}</b> {html.escape(x['detail'] or '')}</small>"
                        for x in q("SELECT * FROM timeline WHERE alert_id=? ORDER BY id", (r["alert_id"],)))
        btn = ""
        if r["status"] == "awaiting_analyst":
            left = max(0, int((r["analyst_deadline"] or 0) - time.time()))
            btn = "".join(f"<form method=post action='/analyst/{r['alert_id']}/{d}' style='display:inline'><button class={c}>{l}</button></form>"
                          for d, l, c in (("approve_lock", "Lock account", "n"), ("approve_hard", "Reset + MFA", "n"), ("dismiss", "Dismiss", "y")))
            btn += f"<br><small>{left}s before soft containment</small>"
        if r["status"] in ("contained_hard", "contained_lock"):
            btn = f"<form method=post action='/revert/{r['alert_id']}'><button class=y>Undo</button></form>"
        rows.append(f"<tr><td>{time.strftime('%H:%M:%S', time.localtime(r['ts']))}</td><td><b>{r['type']}</b></td>"
                    f"<td>{html.escape(r['username'] or '')}{' [privileged]' if r['privileged'] else ''}</td><td>{html.escape(r['ip'] or '')}<br><small>{html.escape(r['geo'] or '')}</small></td>"
                    f"<td>{r['score']} ({r['level']})<br><small>{r['decision']}</small></td>"
                    f"<td><span style='background:{BADGE.get(r['status'],'#444')};color:#fff;padding:2px 8px;border-radius:10px'>{r['status']}</span><br>{btn}</td><td>{t}</td></tr>")
    head = ("<meta http-equiv=refresh content=4><style>body{max-width:1300px}</style><h1>Identity SOC - alerts</h1>"
            "<p>Mails: <a href='http://localhost:8025' target=_blank>Mailpit :8025</a> | "
            "SOAR: <a href='http://localhost:5678' target=_blank>n8n :5678</a> | key = privileged account</p>"
            "<table><tr><th>Time</th><th>Type</th><th>User</th><th>Source</th><th>Risk</th><th>Status</th><th>Timeline</th></tr>")
    return page(head + "".join(rows) + "</table>", "Identity SOC")


# ---------- timeouts (defined behaviour when nobody answers) ----------
def watcher():
    while True:
        try:
            now = time.time()
            for ch in q("SELECT * FROM challenges WHERE status='pending' AND expires<?", (now,)):
                q("UPDATE challenges SET status='timeout' WHERE token_id=?", (ch["token_id"],), write=True)
                set_status(ch["alert_id"], "processing")
                tl(ch["alert_id"], "USER DID NOT ANSWER", "link expired")
                post_n8n("idr-decision", {"source": "user", "alert_id": ch["alert_id"], "answer": "timeout"}, ch["alert_id"])
            for a in q("SELECT * FROM alerts WHERE status='awaiting_analyst' AND analyst_deadline IS NOT NULL AND analyst_deadline<?", (now,)):
                set_status(a["alert_id"], "processing", analyst_deadline=None)
                tl(a["alert_id"], "ANALYST DID NOT ANSWER", "escalation: soft containment only")
                post_n8n("idr-decision", {"source": "analyst", "alert_id": a["alert_id"], "decision": "timeout"}, a["alert_id"])
        except Exception as e:
            log.error("watcher: %s", e)
        time.sleep(3)


init()
threading.Thread(target=watcher, daemon=True).start()
