import requests, urllib3, json
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SEPM_IP="******"; USER="******"; PASS="******"
MD5_HASH="d41d8cd98f00b204e9800998ecf8427e"   # ← ПОСТАВ РЕАЛЬНИЙ MD5 (32 символи)
LIST_NAME="SOC_Test_FP"
BASE=f"https://{SEPM_IP}:8446/sepm/api/v1"

h={"Authorization":"Bearer "+requests.post(f"{BASE}/identity/authenticate",
   json={"username":USER,"password":PASS,"domain":""},verify=False).json()["token"]}
print("Авторизація ОК")

# створюємо fingerprint list з хешем
r=requests.post(f"{BASE}/policy-objects/fingerprints",
   json={"name":LIST_NAME,"description":"test","hashType":"MD5","data":[MD5_HASH]},
   headers=h,verify=False)
print(f"Створення списку: {r.status_code} | {r.text[:200]}")

if r.status_code in (200,201):
    # читаємо назад
    chk=requests.get(f"{BASE}/policy-objects/fingerprints",params={"name":LIST_NAME},headers=h,verify=False)
    print(f"Читання: {chk.status_code}")
    print(f"Хеш у списку: {'Є ✓' if MD5_HASH.lower() in chk.text.lower() else 'НЕМАЄ ✗'}")
