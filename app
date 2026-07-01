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

# знаходимо політику по імені
policies = requests.get(
    f"{BASE_URL}/policies/summary",
    params={"pageSize": 100},
    headers=headers, verify=False
).json()["content"]

target = None
for p in policies:
    if p.get("name", "").strip().lower() == TARGET_POLICY.lower():
        target = p
        break

if not target:
    print(f"Політику '{TARGET_POLICY}' не знайдено. Схожі назви:")
    for p in policies:
        if "app" in p.get("name","").lower() or "soc" in p.get("name","").lower():
            print(f"   • {p.get('name')} | type: {p.get('policytype') or p.get('policyType')}")
    exit(1)

pid = target["id"]
print(f"Знайдено: {target['name']} | ID: {pid}")
print(f"Тип: {target.get('policytype') or target.get('policyType')}\n")

# пробуємо різні endpoints для application control
endpoints = [
    f"{BASE_URL}/policies/adc/{pid}",
    f"{BASE_URL}/policies/application-control/{pid}",
    f"{BASE_URL}/policies/appcontrol/{pid}",
    f"{BASE_URL}/policies/application-device-control/{pid}",
]

for url in endpoints:
    r = requests.get(url, headers=headers, verify=False)
    print(f"GET {url.split('/api/v1')[1]}: {r.status_code}")
    if r.status_code == 200:
        print("   ✓ ПРАЦЮЄ! Ключі:")
        print("   " + str(list(r.json().keys())))
        break
    else:
        print(f"   {r.text[:120]}")
