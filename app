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
cfg=data.get("configuration",{})
print(f"Політика: {data.get('name')}")
print(f"configuration ключі: {list(cfg.keys())}")
print(f"whitelist: {len(cfg.get('whitelistrules',[]))} | blacklist: {len(cfg.get('blacklistrules',[]))}\n")

new_rule={"rulestate":{"enabled":True},"processfile":{"sha2":SHA2,"name":"TEST",
    "company":"","size":0,"description":None,"directory":""},"action":"IGNORE"}

def try_write(label, mutate):
    d=copy.deepcopy(data)
    mutate(d)
    if d.get("desc"): d["desc"]=d["desc"][:1024]
    for method in ("put","patch"):
        r=getattr(requests,method)(f"{BASE}/policies/exceptions/{pid}",json=d,headers=h,verify=False)
        chk=requests.get(f"{BASE}/policies/exceptions/{pid}",headers=h,verify=False).json()
        found=SHA2.lower() in json.dumps(chk).lower()
        print(f"[{method.upper()}] {label}: {r.status_code} | хеш: {'Є ✓✓✓' if found else 'нема'} | {r.text[:100]}")
        if found: return True
    return False

# додаємо в whitelist (створюємо ключ якщо нема)
def m1(d):
    d.setdefault("configuration",{}).setdefault("whitelistrules",[]).append(new_rule)
try_write("новий у whitelist", m1)

# додаємо в blacklist з IGNORE
def m2(d):
    d.setdefault("configuration",{}).setdefault("blacklistrules",[]).append(new_rule)
try_write("новий у blacklist(IGNORE)", m2)
