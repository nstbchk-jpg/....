import requests
import urllib3
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SEPM_IP = "******"
USER    = "******"
PASS    = "******"
TARGET_POLICY = "SOC Test APP"

BASE_URL = f"https://{SEPM_IP}:8446/sepm/api/v1"

token = requests.post(
    f"{BASE_URL}/identity/authenticate",
    json={"username": USER, "password": PASS, "domain": ""},
    verify=False
).json()["token"]
headers = {"Authorization": f"Bearer {token}"}
print("Авторизація ОК\n")

policies = requests.get(
    f"{BASE_URL}/policies/summary",
    params={"pageSize": 100},
    headers=headers, verify=False
).json()["content"]

target = next((p for p in policies if p.get("name","").strip().lower()==TARGET_POLICY.lower()), None)
pid = target["id"]
print(f"Політика: {target['name']} | type: {target.get('policytype')} | id: {pid}\n")

paths = [
    f"/policies/adc-policy/{pid}",
    f"/policies/application-and-device-control/{pid}",
    f"/policies/applicationcontrol/{pid}",
    f"/policies/app-control/{pid}",
    f"/policies/{pid}",
    f"/policies/adc/{pid}",
    f"/adc/{pid}",
    f"/policies/adc-policies/{pid}",
]

working = None
for path in paths:
    r = requests.get(f"{BASE_URL}{path}", headers=headers, verify=False)
    mark = "✓" if r.status_code == 200 else " "
    print(f"[{mark}] GET {path}: {r.status_code}")
    if r.status_code == 200 and working is None:
        working = (path, r.json())

if working:
    path, data = working
    print(f"\n{'='*70}")
    print(f"РОБОЧИЙ ENDPOINT: {path}")
    print(f"{'='*70}")
    print("Ключі верхнього рівня:", list(data.keys()) if isinstance(data, dict) else type(data))
    print(f"\nПовна структура (перші 3000 символів):")
    print(json.dumps(data, indent=2)[:3000])
else:
    print("\nЖоден endpoint не спрацював. Спробуємо через список усіх adc-політик...")
    for p2 in ["/policies/adc-policies", "/policies/adc", "/policies/applicationcontrol"]:
        r = requests.get(f"{BASE_URL}{p2}", params={"pageSize":100}, headers=headers, verify=False)
        print(f"[{'✓' if r.status_code==200 else ' '}] GET {p2}: {r.status_code}")
        if r.status_code == 200:
            print("   " + str(r.json())[:300])
