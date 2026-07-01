import requests, urllib3, json, copy
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SEPM_IP="******"; USER="******"; PASS="******"
TEST_HASH="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA99"
BASE_URL=f"https://{SEPM_IP}:8446/sepm/api/v1"

token=requests.post(f"{BASE_URL}/identity/authenticate",
    json={"username":USER,"password":PASS,"domain":""},verify=False).json()["token"]
headers={"Authorization":f"Bearer {token}"}
print("Авторизація ОК\n")

policies=requests.get(f"{BASE_URL}/policies/summary",params={"pageSize":100},
    headers=headers,verify=False).json()["content"]

target=None
for p in policies:
    d=requests.get(f"{BASE_URL}/policies/exceptions/{p['id']}",headers=headers,verify=False)
    if d.status_code==200:
        cfg=d.json().get("configuration",{})
        if cfg.get("whitelistrules") or cfg.get("blacklistrules"):
            target=(p["id"],p["name"],d.json()); break

pid,pname,data=target
key="whitelistrules" if data["configuration"].get("whitelistrules") else "blacklistrules"
act="IGNORE" if key=="whitelistrules" else "QUARANTINE"
print(f"Політика: {pname} | список: {key}")

new_rule={"rulestate":{"enabled":True},"processfile":{"sha2":TEST_HASH,"name":"PATCH_TEST",
    "company":"","size":0,"description":None,"directory":""},"action":act}

body=copy.deepcopy(data)
body["configuration"][key].append(new_rule)

r=requests.patch(f"{BASE_URL}/policies/exceptions/{pid}",json=body,headers=headers,verify=False)
print(f"PATCH статус: {r.status_code} | {r.text[:150]}")

chk=requests.get(f"{BASE_URL}/policies/exceptions/{pid}",headers=headers,verify=False).json()
print(f"Хеш після PATCH: {'Є ✓✓✓' if TEST_HASH.lower() in json.dumps(chk).lower() else 'НЕМАЄ ✗'}")
