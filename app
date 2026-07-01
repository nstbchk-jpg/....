import requests, urllib3, json, copy
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SEPM_IP="******"; USER="******"; PASS="******"
TEST_POLICY_NAME="SOC Test Exceptions"
SHA2="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA99"
BASE=f"https://{SEPM_IP}:8446/sepm/api/v1"

h={"Authorization":"Bearer "+requests.post(f"{BASE}/identity/authenticate",
   json={"username":USER,"password":PASS,"domain":""},verify=False).json()["token"]}
print("Авторизація ОК")

pols=requests.get(f"{BASE}/policies/summary",params={"pageSize":200},headers=h,verify=False).json()["content"]
target=next(p for p in pols if p.get("name","").strip().lower()==TEST_POLICY_NAME.lower())
pid=target["id"]

data=requests.get(f"{BASE}/policies/exceptions/{pid}",headers=h,verify=False).json()
print(f"Політика: {data.get('name')}")
print(f"Ключі кореня: {list(data.keys())}")
cfg=data.get("configuration",{})
wl=cfg.get("whitelistrules",[])
print(f"whitelist правил: {len(wl)}")

# перевіряємо дублікати по sha2 у наявних правилах
seen={}
for r in wl:
    s=r.get("processfile",{}).get("sha2")
    seen[s]=seen.get(s,0)+1
dups={s:c for s,c in seen.items() if c>1}
print(f"Дублікати sha2 у whitelist: {dups if dups else 'нема'}\n")

new_rule={"rulestate":{"enabled":True},"processfile":{"sha2":SHA2,"name":"TEST",
    "company":"","size":0,"description":None,"directory":""},"action":"IGNORE"}

# ВАРІАНТ 1: повний об'єкт, дедуплікований whitelist, + новий хеш, PUT
d1=copy.deepcopy(data)
uniq=[]; sset=set()
for r in d1["configuration"]["whitelistrules"]:
    s=r.get("processfile",{}).get("sha2")
    if s not in sset:
        uniq.append(r); sset.add(s)
uniq.append(new_rule)
d1["configuration"]["whitelistrules"]=uniq
if d1.get("desc"): d1["desc"]=d1["desc"][:1024]

r1=requests.put(f"{BASE}/policies/exceptions/{pid}",json=d1,headers=h,verify=False)
chk=requests.get(f"{BASE}/policies/exceptions/{pid}",headers=h,verify=False).json()
f1=SHA2.lower() in json.dumps(chk).lower()
print(f"[PUT] повний+дедуплікація: {r1.status_code} | хеш: {'Є ✓✓✓' if f1 else 'нема'} | {r1.text[:120]}")

# ВАРІАНТ 2: PATCH з name + повним configuration
if not f1:
    d2=copy.deepcopy(data)
    d2["configuration"]["whitelistrules"]=uniq
    r2=requests.patch(f"{BASE}/policies/exceptions/{pid}",json=d2,headers=h,verify=False)
    chk=requests.get(f"{BASE}/policies/exceptions/{pid}",headers=h,verify=False).json()
    f2=SHA2.lower() in json.dumps(chk).lower()
    print(f"[PATCH] повний+name: {r2.status_code} | хеш: {'Є ✓✓✓' if f2 else 'нема'} | {r2.text[:120]}")
