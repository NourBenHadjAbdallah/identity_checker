"""Traffic generator: healthy and hostile authentication traffic against Keycloak.
Usage: python simulate.py <warmup|legit|bruteforce|spray|travel|legit_travel|privileged|check USER PASS|all>
The source IP is injected with X-Forwarded-For (Keycloak runs with proxy headers enabled in this lab)."""
import os, sys, time, random, requests

KC = os.getenv("KC_URL", "http://keycloak:8080")
REALM = os.getenv("KC_REALM", "university")
URL = f"{KC}/realms/{REALM}/protocol/openid-connect/token"
STUDENTS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace"]
GOOD = lambda u: "Welcome1!" if u == "dave" else "Str0ng-Pass#" + u
SPRAY_PASSWORDS = ["Password1", "Welcome1!", "Summer2026!"]
CAMPUS = lambda u: f"10.20.1.{10 + (STUDENTS + ['prof.ben', 'registrar']).index(u)}"   # one private IP per user
ATTACKER = {"bruteforce": "203.0.113.50", "spray": "198.51.100.77", "travel": "81.2.69.142",
            "legit_travel": "81.2.69.200", "privileged": "192.0.2.99"}


def login(user, password, ip, quiet=False):
    r = requests.post(URL, data={"grant_type": "password", "client_id": "demo-app", "username": user, "password": password},
                      headers={"X-Forwarded-For": ip}, timeout=10)
    if not quiet:
        print(f"  {user:10s} from {ip:15s} -> {'OK' if r.ok else 'FAIL ' + r.json().get('error_description', r.text)[:50]}")
    return r.ok


def warmup():
    print("[warmup] every user signs in from their own campus IP (builds the baseline)")
    for u in STUDENTS + ["prof.ben", "registrar"]:
        login(u, GOOD(u), CAMPUS(u))


def legit():
    print("[legit] normal day: typos then success, each from own IP -> must raise NO alert")
    for u in STUDENTS:
        if random.random() < 0.7:
            login(u, "typo-" + u, CAMPUS(u))
        login(u, GOOD(u), CAMPUS(u))


def bruteforce(user="erin"):
    print(f"[bruteforce] 8 wrong passwords on {user} from {ATTACKER['bruteforce']}")
    for i in range(8):
        login(user, f"guess{i}", ATTACKER["bruteforce"])
        time.sleep(0.2)


def spray():
    ip = ATTACKER["spray"]
    print(f"[spray] {len(SPRAY_PASSWORDS)} common passwords x {len(STUDENTS)} accounts from {ip}")
    for p in SPRAY_PASSWORDS:
        for u in STUDENTS:
            login(u, p, ip, quiet=False)
            time.sleep(0.15)


def travel(user="bob", key="travel"):
    print(f"[{key}] {user} signs in from campus, then from London seconds later")
    login(user, GOOD(user), CAMPUS(user))
    time.sleep(1)
    login(user, GOOD(user), ATTACKER[key])


def legit_travel():
    travel("carol", "legit_travel")


def privileged():
    print("[privileged] brute force on a privileged account")
    bruteforce("prof.ben")


def check(user, password):
    print(f"[check] can {user} still sign in?")
    login(user, password, CAMPUS(user) if user in STUDENTS + ["prof.ben", "registrar"] else "10.20.1.99")


SC = {"warmup": warmup, "legit": legit, "bruteforce": bruteforce, "spray": spray, "travel": travel,
      "legit_travel": legit_travel, "privileged": privileged}

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "all"
    if cmd == "check":
        check(sys.argv[2], sys.argv[3])
    elif cmd == "all":
        for name in ("warmup", "legit", "bruteforce", "spray", "travel", "legit_travel"):
            SC[name]()
            time.sleep(4)
    else:
        SC[cmd]()
