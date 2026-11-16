import os, time, datetime, requests

KC_URL = os.getenv("KC_URL", "http://keycloak:8080")
REALM = os.getenv("KC_REALM", "university")
KC_ADMIN = os.getenv("KC_ADMIN", "admin")
KC_ADMIN_PASSWORD = os.getenv("KC_ADMIN_PASSWORD", "admin")
N8N_BASE = os.getenv("N8N_BASE", "http://n8n:5678")


class KC:
    """Minimal Keycloak admin client."""

    def __init__(self):
        self._tok, self._exp = None, 0

    def token(self):
        if self._tok and time.time() < self._exp - 10:
            return self._tok
        r = requests.post(
            f"{KC_URL}/realms/master/protocol/openid-connect/token",
            data={"grant_type": "password", "client_id": "admin-cli",
                  "username": KC_ADMIN, "password": KC_ADMIN_PASSWORD},
            timeout=10)
        r.raise_for_status()
        j = r.json()
        self._tok, self._exp = j["access_token"], time.time() + j["expires_in"]
        return self._tok

    def req(self, method, path, **kw):
        r = requests.request(method, f"{KC_URL}/admin/realms/{REALM}{path}",
                             headers={"Authorization": "Bearer " + self.token()},
                             timeout=10, **kw)
        r.raise_for_status()
        return r

    def events(self, since_ms):
        day = datetime.datetime.fromtimestamp(since_ms / 1000, datetime.timezone.utc).strftime("%Y-%m-%d")
        params = [("type", "LOGIN"), ("type", "LOGIN_ERROR"), ("max", 500), ("dateFrom", day)]
        return self.req("GET", "/events", params=params).json()

    def user_by_name(self, username):
        r = self.req("GET", "/users", params={"username": username, "exact": "true"}).json()
        return r[0] if r else None

    def user(self, uid):
        return self.req("GET", f"/users/{uid}").json()

    def groups(self, uid):
        return [g["name"] for g in self.req("GET", f"/users/{uid}/groups").json()]

    def sessions(self, uid):
        return self.req("GET", f"/users/{uid}/sessions").json()

    def logout(self, uid):
        self.req("POST", f"/users/{uid}/logout")

    def update_user(self, uid, rep):
        self.req("PUT", f"/users/{uid}", json=rep)
