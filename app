import requests, urllib3, json
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SEPM_IP="******"; USER="******"; PASS="******"
TEST_POLICY_NAME="ТОЧНА_НАЗВА_ТЕСТОВОЇ"   # ← встав назву своєї тестової exceptions-політики
BASE=f"https://{SEPM_IP}:8446/sepm/api/v1"

h={"Authorization":"Bearer "+requests.post(f"{BASE}/identity/authenticate",
   json={"username":USER,"password":PASS,"domain":""},verify=False).json()["token"]}
print("Авторизація ОК")

pols=requests.get(f"{BASE}/policies/summary",params={"pageSize":200},headers=h,verify=False).json()["content"]
target=next((p for p in pols if p.get("name","").strip().lower()==TEST_POLICY_NAME.lower()),None)

if not target:
    print("Не знайдено. Ось усі політики зі словом test/soc:")
    for p in pols:
        if "test" in p.get("name","").lower() or "soc" in p.get("name","").lower():
            print(f"   • {p.get('name')}  | тип: {p.get('policytype')}")
    exit()

pid=target["id"]
print(f"Політика: {target['name']} | тип: {target.get('policytype')}\n")

data=requests.get(f"{BASE}/policies/exceptions/{pid}",headers=h,verify=False).json()
put=requests.put(f"{BASE}/policies/exceptions/{pid}",json=data,headers=h,verify=False)
print(f"PUT (об'єкт незмінений): {put.status_code}")
print(f"ПОВНА ВІДПОВІДЬ: {put.text}")
