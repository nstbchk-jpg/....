import requests, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SEPM_IP = "******"
USER = "******"
PASS = "******"
DOMAIN = "Default"
BASE = f"https://{SEPM_IP}:8446/sepm/api/v1"

# --- авторизація ---
auth = requests.post(
    f"{BASE}/identity/authenticate",
    json={"username": USER, "password": PASS, "domain": DOMAIN},
    verify=False,
)
auth.raise_for_status()
token = auth.json().get("token") or auth.json().get("accessToken")

# --- список усіх політик ---
headers = {"Authorization": f"Bearer {token}"}
resp = requests.get(f"{BASE}/policies", headers=headers, verify=False)
resp.raise_for_status()
data = resp.json()
policies = data.get("content", data) if isinstance(data, dict) else data

# --- лайтовий вивід ---
for p in policies:
    name = p.get("name", "")
    ptype = str(p.get("policyType") or p.get("type") or "").lower()
    if ptype in ("ac", "adc") or "application" in ptype:
        marker = "  <-- SOC Test APP" if "soc test app" in name.lower() else ""
        print(f"- {name} ({ptype}){marker}")
