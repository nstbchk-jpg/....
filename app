import requests, urllib3, json
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SEPM_IP="******"; USER="******"; PASS="******"
TEST_POLICY="SOC Test Exceptions"
BASE=f"https://{SEPM_IP}:8446/sepm/api/v1"

h={"Authorization":"Bearer "+requests.post(f"{BASE}/identity/authenticate",
   json={"username":USER,"password":PASS,"domain":""},verify=False).json()["token"]}
print("Авторизація ОК\n")

pols=requests.get(f"{BASE}/policies/summary",params={"pageSize":200},headers=h,verify=False).json()["content"]
exc=[p for p in pols if str(p.get("policytype")).lower()=="exceptions"]

# 1) ПОВНА структура твоєї тестової
target=next(p for p in exc if p.get("name","").strip().lower()==TEST_POLICY.lower())
data=requests.get(f"{BASE}/policies/exceptions/{target['id']}",headers=h,verify=False).json()
print("="*70)
print(f"ТВОЯ ТЕСТОВА: {data.get('name')}")
print("="*70)
print(json.dumps(data, indent=2, ensure_ascii=False))
