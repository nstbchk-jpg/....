import requests
import urllib3
import json
import copy

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# НАЛАШТУВАННЯ
# ============================================================
SEPM_IP     = "******"
USER        = "******"
PASS        = "******"
TEST_POLICY = "SOC Test Exceptions"

CHECK_HASH  = "shashashashashashashasha"

# Вибір дії:
#   "IGNORE"     -> дозволити (додається в configuration.applications)
#   "QUARANTINE" -> заблокувати (додається в configuration.blacklistrules)
ACTION = "IGNORE"

BASE = f"https://{SEPM_IP}:8446/sepm/api/v1"

# мапа: дія -> масив у configuration
ACTION_MAP = {
    "IGNORE":     "applications",
    "QUARANTINE": "blacklistrules",
}

if ACTION not in ACTION_MAP:
    print(f"[!] Невірна дія '{ACTION}'. Допустимо: IGNORE або QUARANTINE")
    exit(1)

target_key = ACTION_MAP[ACTION]

# ============================================================
# Авторизація
# ============================================================
print("\033[90m[-] Авторизація...\033[0m")
try:
    token = requests.post(
        f"{BASE}/identity/authenticate",
        json={"username": USER, "password": PASS, "domain": ""},
        verify=False
    ).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("\033[32m[V] Авторизація успішна.\033[0m")
except Exception as e:
    print(f"\033[31m[!] Помилка авторизації: {e}\033[0m")
    exit(1)

# ============================================================
# Пошук політики
# ============================================================
pols = requests.get(
    f"{BASE}/policies/summary",
    params={"pageSize": 200},
    headers=headers, verify=False
).json()["content"]

target = next((p for p in pols if p.get("name", "").strip().lower() == TEST_POLICY.lower()), None)
if not target:
    print(f"\033[31m[!] Політику '{TEST_POLICY}' не знайдено.\033[0m")
    exit(1)

pid = target["id"]
print(f"\033[32m[V] Політика: {TEST_POLICY}\033[0m")
print(f"\033[90m    Дія: {ACTION} -> configuration.{target_key}\033[0m")

# ============================================================
# Читаємо політику, перевіряємо дубль
# ============================================================
data = requests.get(f"{BASE}/policies/exceptions/{pid}", headers=headers, verify=False).json()

if CHECK_HASH.lower() in json.dumps(data).lower():
    print(f"\033[33m[i] Хеш вже присутній у політиці. Нічого не додаємо.\033[0m")
    exit(0)

# ============================================================
# Формуємо правило і додаємо у потрібний масив
# ============================================================
new_rule = {
    "rulestate": {"enabled": True},
    "processfile": {
        "sha2": CHECK_HASH,
        "name": "added_by_script.exe",
        "company": "",
        "size": 0,
        "description": None,
        "directory": ""
    },
    "action": ACTION
}

body = copy.deepcopy(data)
body.setdefault("configuration", {}).setdefault(target_key, []).append(new_rule)
if body.get("desc"):
    body["desc"] = body["desc"][:1024]

# ============================================================
# Запис (PATCH) + підтвердження
# ============================================================
r = requests.patch(f"{BASE}/policies/exceptions/{pid}", json=body, headers=headers, verify=False)

chk = requests.get(f"{BASE}/policies/exceptions/{pid}", headers=headers, verify=False).json()
found = CHECK_HASH.lower() in json.dumps(chk).lower()

if found:
    print(f"\033[32m[+] Хеш успішно додано ({ACTION}).\033[0m")
    print(f"\033[32m    {CHECK_HASH}\033[0m")
else:
    print(f"\033[31m[!] Не вдалося додати. Статус: {r.status_code} | {r.text[:150]}\033[0m")
