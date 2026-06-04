"""
Verify all 4 Part-B attacks are BLOCKED on the secure build.
Run with the secure server (default):
  python manage.py runserver
"""
import requests

BASE = "http://127.0.0.1:8000"
PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"


def get_csrf(session, url):
    r = session.get(url)
    for line in r.text.splitlines():
        if 'csrfmiddlewaretoken' in line:
            return line.split('value="')[1].split('"')[0]
    return ""


def register_user(session, username, email, password):
    url = f"{BASE}/register"
    csrf = get_csrf(session, url)
    return session.post(url, data={
        "csrfmiddlewaretoken": csrf,
        "username": username,
        "email": email,
        "password": password,
        "password2": password,
    }, allow_redirects=True)


def login_user(session, username, password):
    url = f"{BASE}/login"
    csrf = get_csrf(session, url)
    return session.post(url, data={
        "csrfmiddlewaretoken": csrf,
        "username": username,
        "password": password,
    }, allow_redirects=True)


def add_client(session, name, phone="0501234567"):
    url = f"{BASE}/clients/add"
    csrf = get_csrf(session, url)
    return session.post(url, data={
        "csrfmiddlewaretoken": csrf,
        "name": name,
        "phone": phone,
    }, allow_redirects=True)


print("\n" + "="*55)
print("  SECURE BUILD — attacks should ALL be blocked")
print("="*55)

# ── Fix 2: SQLi Login blocked ────────────────────────────────
print("\n[Fix 2] SQLi Login — should be blocked by ORM")
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
    print(f"  {FAIL} SQLi login SUCCEEDED — secure build not active?")
else:
    print(f"  {PASS} SQLi login blocked — stayed on login page")

# ── Fix 3: SQLi Register blocked ────────────────────────────
print("\n[Fix 3] SQLi Register — duplicate check should use ORM")
s3 = requests.Session()
register_user(s3, "alice", "alice@test.com", "Abc123456!X")
r = register_user(s3, "' AND '1'='2'#", "alice@test.com", "Abc123456!X")
if "already exists" in r.text:
    print(f"  {PASS} Duplicate email correctly blocked ('already exists' shown)")
elif r.status_code == 500:
    print(f"  {FAIL} Server 500 — unexpected error")
else:
    print(f"  {FAIL} Duplicate check was bypassed — secure build not active?")

# ── Fix 1: XSS blocked ──────────────────────────────────────
print("\n[Fix 1] Stored XSS — script tag should be HTML-escaped")
s1 = requests.Session()
register_user(s1, "xsstest", "xsstest@test.com", "Abc123456!X")
login_user(s1, "xsstest", "Abc123456!X")
xss_payload = '<script>alert(document.cookie)</script>'
r = add_client(s1, xss_payload)
if xss_payload in r.text:
    print(f"  {FAIL} Raw <script> tag in HTML — XSS NOT fixed")
elif "&lt;script&gt;" in r.text or "alert" in r.text:
    print(f"  {PASS} Script tag is HTML-escaped — XSS blocked (rendered as text)")
else:
    r2 = s1.get(f"{BASE}/clients/")
    if xss_payload in r2.text:
        print(f"  {FAIL} Raw <script> tag in client list — XSS NOT fixed")
    elif "&lt;script&gt;" in r2.text or "alert" in r2.text:
        print(f"  {PASS} Script tag is HTML-escaped in client list — XSS blocked")
    else:
        print(f"  {PASS} Payload not rendered as script (escaped or absent)")

# ── Fix 4: SQLi Add Client blocked ──────────────────────────
print("\n[Fix 4] SQLi Add Client — ORM should safely store the payload as text")
s4 = requests.Session()
register_user(s4, "sqlitest", "sqlitest@test.com", "Abc123456!X")
login_user(s4, "sqlitest", "Abc123456!X")
payload = "'); DROP TABLE clients_client; --"
r = add_client(s4, payload)
if r.status_code == 500:
    print(f"  {FAIL} Server 500 — raw SQL still being used?")
elif "/clients/" in r.url and r.status_code == 200:
    print(f"  {PASS} Payload stored safely as text, redirected to detail page (ORM used)")
else:
    print(f"  {FAIL} Unexpected response — status {r.status_code}, url {r.url}")

print("\n" + "="*55 + "\n")
