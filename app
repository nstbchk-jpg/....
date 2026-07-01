import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SEPM_IP = "******"
USER    = "******"
PASS    = "******"

BASE_URL = f"https://{SEPM_IP}:8446/sepm/api/v1"

token = requests.post(
    f"{BASE_URL}/identity/authenticate",
    json={"username": USER, "password": PASS, "domain": ""},
    verify=False
).json()["token"]
headers = {"Authorization": f"Bearer {token}"}
print("Авторизація ОК\n")

# перебираємо можливі кореневі ADC endpoints (без ID) — шукаємо хоч 200/400/500, не 404
roots = [
    "/policies/adc",
    "/policies/adc-policies",
    "/policies/applicationcontrol",
    "/policies/application-control",
    "/policies/appcontrol",
    "/policies/app-device-control",
    "/policies/adc-policy",
]

print("Пошук будь-якого живого ADC-кореня (не-404 = існує):\n")
for r in roots:
    resp = requests.get(f"{BASE_URL}{r}", params={"pageSize":10}, headers=headers, verify=False)
    alive = "◄ ЖИВИЙ" if resp.status_code != 404 else ""
    print(f"  {resp.status_code:>3}  GET {r}   {alive}")
