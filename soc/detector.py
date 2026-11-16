"""Detector: polls Keycloak login events and raises alerts to the SOAR (n8n).
Detections are written here, NOT delegated to Keycloak's built-in brute-force protection
(which is disabled in the realm on purpose)."""
import os, time, uuid, sqlite3, logging, collections, requests
from common import KC, N8N_BASE
import geo

logging.basicConfig(level=logging.INFO, format="%(asctime)s detector %(message)s")
log = logging.getLogger("detector")

BF_N = int(os.getenv("BF_THRESHOLD", "5"))        # failures on one account
BF_WIN = int(os.getenv("BF_WINDOW", "120"))       # seconds
SPRAY_USERS = int(os.getenv("SPRAY_USERS", "5"))  # distinct accounts from one IP
SPRAY_WIN = int(os.getenv("SPRAY_WINDOW", "300"))
SAF_N = int(os.getenv("SAF_FAILURES", "3"))       # failures from one IP before a success
SAF_WIN = int(os.getenv("SAF_WINDOW", "300"))
TRAVEL_KMH = float(os.getenv("TRAVEL_KMH", "900"))
TRAVEL_MIN_KM = float(os.getenv("TRAVEL_MIN_KM", "500"))
COOLDOWN = int(os.getenv("COOLDOWN", "300"))
POLL = float(os.getenv("POLL_SECONDS", "2"))
DB = os.getenv("DETECTOR_DB", "/data/detector.db")
ABUSE_KEY = os.getenv("ABUSEIPDB_KEY", "")  # optional

kc = KC()
fails = collections.deque()          # (t, ip, username)
seen = collections.deque(maxlen=20000)
seen_set = set()
cool = {}
ucache = {}
acache = {}


def db():
    c = sqlite3.connect(DB)
    c.execute("CREATE TABLE IF NOT EXISTS known(username TEXT, ip TEXT, PRIMARY KEY(username, ip))")
    c.execute("CREATE TABLE IF NOT EXISTS last(username TEXT PRIMARY KEY, ip TEXT, lat REAL, lon REAL, t REAL)")
    return c


def user_info(username):
    c = ucache.get(username)
    if c and time.time() - c[0] < 60:
        return c[1]
    info = {"user_id": None, "email": None, "privileged": False}
    try:
        u = kc.user_by_name(username)
        if u:
            info = {"user_id": u["id"], "email": u.get("email"),
                    "privileged": "Privileged" in kc.groups(u["id"])}
    except Exception as e:
        log.warning("user lookup failed: %s", e)
    ucache[username] = (time.time(), info)
    return info


def abuse_score(ip):
    if not ABUSE_KEY or geo.lookup(ip) and geo.lookup(ip)[0].startswith("Campus"):
        return None
    if ip in acache:
        return acache[ip]
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check", timeout=5,
                         headers={"Key": ABUSE_KEY, "Accept": "application/json"},
                         params={"ipAddress": ip, "maxAgeInDays": 90})
        acache[ip] = r.json()["data"]["abuseConfidenceScore"]
    except Exception:
        acache[ip] = None
    return acache[ip]


def emit(kind, key, **kw):
    now = time.time()
    if now - cool.get((kind, key), 0) < COOLDOWN:
        return
    cool[(kind, key)] = now
    loc = geo.lookup(kw.get("ip", ""))
    payload = {"alert_id": uuid.uuid4().hex[:12], "type": kind, "detected_at": now,
               "geo": loc[0] if loc else "Unknown", "abuse_score": abuse_score(kw.get("ip", "")), **kw}
    log.info("ALERT %s %s", kind, {k: v for k, v in payload.items() if k in ("user", "ip", "count")})
    try:
        requests.post(f"{N8N_BASE}/webhook/idr-alert", json=payload, timeout=10)
    except Exception as e:
        log.error("cannot reach n8n: %s", e)


def on_failure(t, ip, uname):
    fails.append((t, ip, uname))
    while fails and t - fails[0][0] > 600:
        fails.popleft()
    # 1) brute force on one account
    n = sum(1 for (ft, _, u) in fails if u == uname and t - ft <= BF_WIN)
    if n >= BF_N:
        info = user_info(uname)
        c = db()
        new_ip = c.execute("SELECT 1 FROM known WHERE username=? AND ip=?", (uname, ip)).fetchone() is None
        c.close()
        emit("brute_force", uname, user=uname, ip=ip, count=n, new_ip=new_ip, event_time=t, **info)
    # 2) password spraying from one IP
    users = {u for (ft, fip, u) in fails if fip == ip and t - ft <= SPRAY_WIN}
    if len(users) >= SPRAY_USERS:
        emit("spraying", ip, user="(multiple)", users=sorted(users), ip=ip, count=len(users),
             new_ip=True, event_time=t, user_id=None, email=None, privileged=False)


def on_success(t, ip, uname):
    info = user_info(uname)
    c = db()
    new_ip = c.execute("SELECT 1 FROM known WHERE username=? AND ip=?", (uname, ip)).fetchone() is None
    # 3) success after failures from the same IP = probable compromise
    nf = sum(1 for (ft, fip, _) in fails if fip == ip and t - ft <= SAF_WIN)
    if nf >= SAF_N:
        emit("success_after_failures", uname, user=uname, ip=ip, count=nf, new_ip=new_ip, event_time=t, **info)
    # 4) impossible travel
    loc = geo.lookup(ip)
    prev = c.execute("SELECT ip, lat, lon, t FROM last WHERE username=?", (uname,)).fetchone()
    if loc and prev and prev[0] != ip:
        km = geo.haversine_km(prev[1], prev[2], loc[1], loc[2])
        hours = max((t - prev[3]) / 3600.0, 1 / 3600.0)
        if km >= TRAVEL_MIN_KM and km / hours > TRAVEL_KMH:
            emit("impossible_travel", uname, user=uname, ip=ip, count=1, new_ip=new_ip, event_time=t,
                 detail=f"{round(km)} km in {round(hours*3600)} s from {prev[0]}", **info)
    if loc:
        c.execute("INSERT OR REPLACE INTO last VALUES(?,?,?,?,?)", (uname, ip, loc[1], loc[2], t))
    c.execute("INSERT OR IGNORE INTO known VALUES(?,?)", (uname, ip))
    c.commit()
    c.close()


def handle(ev):
    key = (ev["time"], ev["type"], ev.get("userId"), ev.get("ipAddress"), ev.get("error"))
    if key in seen_set:
        return
    if len(seen) == seen.maxlen:
        seen_set.discard(seen[0])
    seen.append(key)
    seen_set.add(key)
    uname = ((ev.get("details") or {}).get("username") or "").lower()
    ip, t = ev.get("ipAddress", "?"), ev["time"] / 1000.0
    if not uname:
        return
    if ev["type"] == "LOGIN_ERROR":
        on_failure(t, ip, uname)
    elif ev["type"] == "LOGIN":
        on_success(t, ip, uname)


def main():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    start_ms = int(time.time() * 1000)
    last_ms = start_ms
    log.info("started; thresholds BF=%s/%ss SPRAY=%s users SAF=%s", BF_N, BF_WIN, SPRAY_USERS, SAF_N)
    while True:
        try:
            evs = [e for e in kc.events(last_ms) if e["time"] >= last_ms - 5000]
            for ev in sorted(evs, key=lambda e: e["time"]):
                handle(ev)
                last_ms = max(last_ms, ev["time"])
        except Exception as e:
            log.warning("poll error (Keycloak not ready?): %s", e)
            time.sleep(5)
        time.sleep(POLL)


if __name__ == "__main__":
    main()
