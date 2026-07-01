import requests, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SEPM_IP="******"; USER="******"; PASS="******"
BASE=f"https://{SEPM_IP}:8446/sepm/api/v1"

h={"Authorization":"Bearer "+requests.post(f"{BASE}/identity/authenticate",
   json={"username":USER,"password":PASS,"domain":""},verify=False).json()["token"]}
print("Авторизація ОК\n")

# знаходимо ID політики SOC Test APP
pols=requests.get(f"{BASE}/policies/summary",params={"pageSize":200},headers=h,verify=False).json()["content"]
adc=next((p for p in pols if p.get("name","").strip().lower()=="soc test app"),None)
pid=adc["id"] if adc else "NOID"
print(f"SOC Test APP id: {pid} | type: {adc.get('policytype') if adc else '-'}\n")

paths=[
    f"/policies/adc/{pid}", f"/policies/adc", f"/policies/app-control/{pid}",
    f"/policies/applicationcontrol/{pid}", f"/policies/application-control/{pid}",
    f"/policies/appcontrol/{pid}", f"/policies/application-device-control/{pid}",
    f"/policies/adc-policy/{pid}", f"/policies/raw/adc/{pid}",
    f"/policies/raw/app/{pid}", f"/policies/raw/{pid}",
]
print("Перевірка ADC-endpoint'ів (не-404 = існує):\n")
for p in paths:
    r=requests.get(f"{BASE}{p}",headers=h,verify=False)
    mark="◄◄◄ ЖИВИЙ!" if r.status_code!=404 else ""
    print(f"  {r.status_code}  GET {p}  {mark}")
