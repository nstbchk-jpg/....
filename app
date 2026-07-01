import requests, urllib3, json, copy
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SEPM_IP="******"; USER="******"; PASS="******"
TEST_POLICY="SOC Test Exceptions"
SHA2="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA99"
ADD_IGNORE=True   # True=IGNORE(applications), False=QUARANTINE(blacklistrules)
BASE=f"https://{SEPM_IP}:8446/sepm/api/v1"

h={"Authorization":"Bearer "+requests.post(f"{BASE}/identity/authenticate",
   json={"username":USER,"password":PASS,"domain":""},verify=False).json()["token"]}
print("Авторизація ОК")

pols=requests.get(f"{BASE}/policies/summary",params={"pageSize":200},headers=h,verify=False).json()["content"]
target=next(p for p in pols if p.get("name","").strip().lower()==TEST_POLICY.lower())
pid=target["id"]

data=requests.get(f"{BASE}/policies/exceptions/{pid}",headers=h,verify=False).json()

key = "applications" if ADD_IGNORE else "blacklistrules"
action = "IGNORE" if ADD_IGNORE else "QUARANTINE"

new_rule={
    "rulestate":{"enabled":True},
    "processfile":{"sha2":SHA2,"name":"SOC_TEST_ADD.exe","company":"",
                   "size":0,"description":None,"directory":""},
    "action":action
}

# перевірка на дубль
already = SHA2.lower() in json.dumps(data).lower()
print(f"Хеш вже в політиці: {'так' if already else 'ні'}")

body=copy.deepcopy(data)
body.setdefault("configuration",{}).setdefault(key,[]).append(new_rule)
if body.get("desc"): body["desc"]=body["desc"][:1024]

for method in ("put","patch"):
    b=copy.deepcopy(body)
    r=getattr(requests,method)(f"{BASE}/policies/exceptions/{pid}",json=b,headers=h,verify=False)
    chk=requests.get(f"{BASE}/policies/exceptions/{pid}",headers=h,verify=False).json()
    found=SHA2.lower() in json.dumps(chk).lower()
    print(f"[{method.upper()}] {r.status_code} | хеш у '{key}' після: {'Є ✓✓✓' if found else 'нема'} | {r.text[:120]}")
    if found:
        print(">>> ПРАЦЮЄ! Пишемо в configuration."+key)
        break
