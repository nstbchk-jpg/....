import requests, urllib3, json
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
print(f"Політика: {target['name']}\n")

new_rule={"rulestate":{"enabled":True},"processfile":{"sha2":SHA2,"name":"TEST",
    "company":"","size":0,"description":None,"directory":""},"action":"IGNORE"}

# ТІЛО ТІЛЬКИ З НОВИМ ПРАВИЛОМ, без існуючих
variants = [
    ("тільки whitelistrules на корені", {"whitelistrules":[new_rule]}),
    ("configuration з тільки новим", {"configuration":{"whitelistrules":[new_rule]}}),
    ("add_whitelist", {"add_whitelistrules":[new_rule]}),
]

for name,body in variants:
    for method in ("put","patch"):
        r=getattr(requests,method)(f"{BASE}/policies/exceptions/{pid}",json=body,headers=h,verify=False)
        chk=requests.get(f"{BASE}/policies/exceptions/{pid}",headers=h,verify=False).json()
        found=SHA2.lower() in json.dumps(chk).lower()
        print(f"[{method.upper()}] {name}: {r.status_code} | хеш: {'Є ✓✓✓' if found else 'нема'} | {r.text[:90]}")
        if found:
            print("\n>>> ЗНАЙШЛИ РОБОЧИЙ ВАРІАНТ!")
            break
