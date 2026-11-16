"""Automated evaluation: replays every scenario, plays the user/analyst through the real
mail + dashboard channels, then prints detection, false-positive, latency and friction metrics."""
import os, re, sys, time, requests
import simulate as sim

API = os.getenv("SOC_API_URL", "http://soc-api:8000")
MAILPIT = os.getenv("MAILPIT_URL", "http://mailpit:8025")
MANUAL_BASELINE_S = int(os.getenv("MANUAL_BASELINE_S", "900"))   # assumption: 15 min for a human to react
FINAL = {"logged", "closed", "contained_soft", "contained_hard", "contained_lock", "reverted", "verification_failed"}

# scenario -> (function, expected alert type, who answers)
SCENARIOS = [
    ("bruteforce", sim.bruteforce, "brute_force", "erin", "user_no"),
    ("travel (attack)", sim.travel, "impossible_travel", "bob", "user_no"),
    ("travel (real trip)", sim.legit_travel, "impossible_travel", "carol", "user_yes"),
    ("spraying", sim.spray, "spraying", "(multiple)", "none"),
    ("spray success", None, "success_after_failures", "dave", "analyst_hard"),
    ("privileged brute force", sim.privileged, "brute_force", "prof.ben", "analyst_dismiss_timeout"),
]


def alerts():
    return requests.get(f"{API}/api/alerts", timeout=10).json()


def click_mail(to, answer):
    """Read the real e-mail in Mailpit, open the signed link, press the button."""
    for _ in range(20):
        msgs = requests.get(f"{MAILPIT}/api/v1/messages", timeout=10).json().get("messages", [])
        for m in msgs:
            if any(t["Address"] == f"{to}@univ.test" for t in m["To"]):
                body = requests.get(f"{MAILPIT}/api/v1/message/{m['ID']}", timeout=10).json()["Text"]
                mt = re.search(r"/u/([\w\-\.]+)", body)
                if mt:
                    requests.delete(f"{MAILPIT}/api/v1/messages", json={"IDs": [m["ID"]]}, timeout=10)
                    r = requests.post(f"{API}/u/{mt.group(1)}/{answer}", timeout=10)
                    return r.ok
        time.sleep(1)
    return False


def wait_alert(atype, user, since, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        for a in alerts():
            if a["type"] == atype and a["username"] == user and a["ts"] >= since:
                return a
        time.sleep(1)
    return None


def wait_final(aid, timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        a = next(x for x in alerts() if x["alert_id"] == aid)
        if a["status"] in FINAL:
            return a
        time.sleep(1)
    return a


def main():
    sim.warmup()
    time.sleep(3)
    since = time.time()
    print("\n== healthy traffic (must raise nothing) ==")
    sim.legit()
    time.sleep(8)
    fp = [a for a in alerts() if a["ts"] >= since]
    print(f"false positives on healthy traffic: {len(fp)}")

    rows, disturbed = [], 0
    t0 = time.time()
    for name, fn, atype, user, mode in SCENARIOS:
        if fn:
            t0 = time.time()
            print(f"\n== {name} ==")
            fn()
        a = wait_alert(atype, user, t0)
        if not a:
            rows.append((name, atype, "MISSED", "-", "-", "-", "-"))
            continue
        lat = (a["detected_at"] or a["ts"]) - (a["event_time"] or t0)
        if mode.startswith("user"):
            disturbed += 1
            click_mail(user, "yes" if mode == "user_yes" else "no")
        elif mode == "analyst_hard":
            time.sleep(1)
            requests.post(f"{API}/analyst/{a['alert_id']}/approve_hard")
        elif mode.startswith("analyst_dismiss_timeout"):
            print("   (analyst stays silent on purpose: waiting for the escalation delay...)")
        a = wait_final(a["alert_id"], timeout=int(os.getenv("ANALYST_TTL", "180")) + 30 if mode.startswith("analyst_dismiss") else 40)
        act = [x for x in a["timeline"] if x["event"].startswith("RESPONSE")]
        t_contain = (act[-1]["ts"] - a["ts"]) if act else None
        rows.append((name, atype, "detected", f"{lat:.1f}s", f"{a['score']} -> {a['decision']}", a["status"],
                     f"{t_contain:.1f}s" if t_contain is not None else "-"))

    print("\n" + "=" * 100)
    print(f"{'scenario':24s}{'expected':24s}{'result':10s}{'detect':8s}{'score->decision':22s}{'final status':18s}{'alert->action'}")
    for r in rows:
        print(f"{r[0]:24s}{r[1]:24s}{r[2]:10s}{r[3]:8s}{r[4]:22s}{r[5]:18s}{r[6]}")
    det = sum(1 for r in rows if r[2] == "detected")
    print("-" * 100)
    print(f"detection rate           : {det}/{len(rows)}")
    print(f"false positives (healthy): {len(fp)}")
    print(f"legit users disturbed    : {disturbed} question(s) sent ({sum(1 for r in rows if 'real trip' in r[0])} of them were genuine travel)")
    print(f"manual baseline          : ~{MANUAL_BASELINE_S}s per alert; automated alert->action is shown in the last column")


if __name__ == "__main__":
    main()
