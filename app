import requests, urllib3, json
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SEPM_IP="******"; USER="******"; PASS="******"
BASE=f"https://{SEPM_IP}:8446/sepm/api/v1"

h={"Authorization":"Bearer "+requests.post(f"{BASE}/identity/authenticate",
   json={"username":USER,"password":PASS,"domain":""},verify=False).json()["token"]}
print("Авторизація ОК")

pols=requests.get(f"{BASE}/policies/summary",params={"pageSize":200},headers=h,verify=False).json()["content"]
exc=[p for p in pols if str(p.get("policytype")).lower()=="exceptions"]
pid,pname=exc[0]["id"],exc[0]["name"]
print(f"Політика: {pname}")

data=requests.get(f"{BASE}/policies/exceptions/{pid}",headers=h,verify=False).json()
old=data.get("desc","")
print(f"desc ДО: '{old[:50]}'")

MARK="MARKER_9271"
data["desc"]=MARK

put=requests.put(f"{BASE}/policies/exceptions/{pid}",json=data,headers=h,verify=False)
print(f"PUT: {put.status_code}")

chk=requests.get(f"{BASE}/policies/exceptions/{pid}",headers=h,verify=False).json()
print(f"desc ПІСЛЯ: '{chk.get('desc','')[:50]}'")
print(f">>> PUT реально пише: {'ТАК' if chk.get('desc')==MARK else 'НІ — endpoint не редагує взагалі'}")
