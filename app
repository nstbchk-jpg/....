import requests, urllib3, json, copy
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SEPM_IP="******"; USER="******"; PASS="******"
TEST_POLICY="SOC Test Exceptions"
SHA2="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA99"
BASE=f"https://{SEPM_IP}:8446/sepm/api/v1"

h={"Authorization":"Bearer "+requests.post(f"{BASE}/identity/authenticate",
   json={"username":USER,"password":PASS,"domain":""},verify=False).json()["token"]}
print("Авторизація ОК\n")

pols=requests.get(f"{BASE}/policies/summary",params={"pageSize":200},headers=h,verify=False).json()["content"]
exc=[p for p in pols if str(p.get("policytype")).lower()=="exceptions"]

# 1) знаходимо ЕТАЛОННЕ whitelist-правило з будь-якої заповненої політики
template=None
for p in exc:
    d=requests.get(f"{BASE}/policies/exceptions/{p['id']}",headers=h,verify=False)
    if d.status_code!=200: continue
    wl=d.json().get("configuration",{}).get("whitelistrules",[])
    if wl:
        template=copy.deepcopy(wl[0])
        print(f"Еталон узято з: {p['name']}")
        print(json.dumps(template,indent=2,ensure_ascii=False))
        break

if not template:
    print("Ніде нема whitelist-правила для еталону")
    exit()

# 2) робимо з еталону нове правило зі своїм хешем
new_rule=copy.deepcopy(template)
new_rule["processfile"]["sha2"]=SHA2
new_rule["processfile"]["name"]="SOC_TEST_ADD"
for f in ("company","directory"): new_rule["processfile"][f]=""
new_rule["processfile"]["size"]=0
new_rule["processfile"]["description"]=None

# 3) пишемо у ТВОЮ тестову
target=next(p for p in exc if p.get("name","").strip().lower()==TEST_POLICY.lower())
pid=target["id"]
data=requests.get(f"{BASE}/policies/exceptions/{pid}",headers=h,verify=False).json()

for method in ("put","patch"):
    body=copy.deepcopy(data)
    body.setdefault("configuration",{}).setdefault("whitelistrules",[]).append(copy.deepcopy(new_rule))
    if body.get("desc"): body["desc"]=body["desc"][:1024]
    r=getattr(requests,method)(f"{BASE}/policies/exceptions/{pid}",json=body,headers=h,verify=False)
    chk=requests.get(f"{BASE}/policies/exceptions/{pid}",headers=h,verify=False).json()
    found=SHA2.lower() in json.dumps(chk).lower()
    print(f"\n[{method.upper()}] {r.status_code} | хеш у SOC Test Exceptions: {'Є ✓✓✓' if found else 'нема'} | {r.text[:150]}")
    if found:
        print(">>> ПРАЦЮЄ! Використовуємо цей метод."); break
