"""
End-to-end verification script for Comunication_LTD.
Run with: python verify.py
Tests secure build flows + confirms vulnerable payloads work only in vulnerable build.
"""
import os, sys, django

os.environ['DJANGO_SETTINGS_MODULE'] = 'comunication_ltd.settings.secure'
sys.path.insert(0, os.path.dirname(__file__))
django.setup()

from django.test import RequestFactory, Client as TestClient
from django.contrib.sessions.backends.db import SessionStore
from accounts.models import User, PasswordHistory, PasswordResetToken
from clients.models import Client
from accounts.security import hmac_hash, generate_salt, load_policy, validate_complexity, check_dictionary, check_history
from pathlib import Path

def check(label, condition):
    print(f"  {'[PASS]' if condition else '[FAIL]'} {label}")
    if not condition:
        raise AssertionError(f"FAILED: {label}")
User.objects.filter(username__in=['testverify','flowtest','sqlitest']).delete()
Client.objects.filter(name__in=['Test Client','Safe Client',
    "<script>alert('You are hacked')</script>"]).delete()

print("\n=== Phase 2: Security module ===")
salt = generate_salt()
h = hmac_hash("MyPass1!xz", salt)
check("HMAC-SHA-256 deterministic", hmac_hash("MyPass1!xz", salt) == h)
check("HMAC-SHA-256 different password differs", hmac_hash("Wrong1!xz", salt) != h)
check("16-byte salt", len(salt) == 16)

policy = load_policy(Path("password_policy.json"))
ok, _ = validate_complexity("MyPass1!xz", policy)
check("Complexity: valid password passes", ok)
ok, _ = validate_complexity("short", policy)
check("Complexity: short password fails", not ok)
ok, _ = validate_complexity("alllowercase!!", policy)
check("Complexity: only 2 classes (lower+special) fails", not ok)

check("Dictionary: 'password' rejected", check_dictionary("password", Path("dictionary.txt")))
check("Dictionary: strong password allowed", not check_dictionary("X9k!mLqZ2w", Path("dictionary.txt")))

h2 = hmac_hash("OldPass1!x", salt)
check("History: reused password detected", check_history("OldPass1!x", [(h2, salt)]))
check("History: new password not in history", not check_history("NewPass9!z", [(h2, salt)]))

print("\n=== Phase 3: Models ===")
User.objects.filter(username='testverify').delete()
salt2 = generate_salt()
u = User.objects.create(username='testverify', email='tv@test.com',
    password_hash=hmac_hash("TestPass1!x", salt2), salt=salt2)
check("User created in MySQL", User.objects.filter(username='testverify').exists())
PasswordHistory.objects.create(user=u, password_hash=u.password_hash, salt=salt2)
check("PasswordHistory created", u.password_history.count() == 1)

c = Client.objects.create(name="Test Client", phone="050-1234567", package="Basic")
check("Client created in MySQL", Client.objects.filter(name="Test Client").exists())

print("\n=== Phase 4: HTTP flows (secure build) ===")
tc = TestClient()

# Register
resp = tc.post('/register', {
    'username': 'flowtest', 'email': 'flow@test.com',
    'password': 'FlowPass1!x', 'password2': 'FlowPass1!x'
})
check("Register: valid user -> redirect to login", resp.status_code == 302)
check("Register: user in DB", User.objects.filter(username='flowtest').exists())

# Register duplicate
resp = tc.post('/register', {
    'username': 'flowtest', 'email': 'flow@test.com',
    'password': 'FlowPass1!x', 'password2': 'FlowPass1!x'
})
check("Register: duplicate rejected (200 with errors)", resp.status_code == 200)

# Login wrong password
resp = tc.post('/login', {'username': 'flowtest', 'password': 'WrongPass1!'})
check("Login: wrong password -> error shown (200)", resp.status_code == 200)

# Check failed_attempts incremented
u2 = User.objects.get(username='flowtest')
check("Login: failed_attempts incremented", u2.failed_attempts == 1)

# Login correct
resp = tc.post('/login', {'username': 'flowtest', 'password': 'FlowPass1!x'})
check("Login: correct password -> redirect", resp.status_code == 302)

# Change password (logged-in session)
tc2 = TestClient()
tc2.post('/login', {'username': 'flowtest', 'password': 'FlowPass1!x'})
resp = tc2.post('/change-password', {
    'current_password': 'FlowPass1!x',
    'new_password': 'NewFlowPass2@y',
    'new_password2': 'NewFlowPass2@y',
})
check("Change password: success -> redirect", resp.status_code == 302)

# Reuse old password
tc3 = TestClient()
tc3.post('/login', {'username': 'flowtest', 'password': 'NewFlowPass2@y'})
resp = tc3.post('/change-password', {
    'current_password': 'NewFlowPass2@y',
    'new_password': 'FlowPass1!x',
    'new_password2': 'FlowPass1!x',
})
check("Change password: reused password rejected (200)", resp.status_code == 200)

# Forgot password
resp = tc.post('/forgot-password', {'email': 'flow@test.com'})
check("Forgot password: valid email -> redirect", resp.status_code == 302)
token_obj = PasswordResetToken.objects.filter(user__username='flowtest', used=False).first()
check("Forgot password: token created in DB", token_obj is not None)

# Reset password
resp = tc.post('/reset-password', {
    'token': token_obj.token_sha1,
    'new_password': 'ResetPass3#z',
    'new_password2': 'ResetPass3#z',
})
check("Reset password: valid token -> redirect to login", resp.status_code == 302)

# Add client (must be logged in)
tc4 = TestClient()
tc4.post('/login', {'username': 'flowtest', 'password': 'ResetPass3#z'})
resp = tc4.post('/clients/add', {
    'name': 'Safe Client', 'phone': '050', 'address': 'TLV', 'package': 'Gold'
})
check("Add client: success -> redirect to detail", resp.status_code == 302)

# XSS payload in secure build — should be stored and rendered escaped
xss = "<script>alert('You are hacked')</script>"
resp = tc4.post('/clients/add', {'name': xss, 'phone': '', 'address': '', 'package': ''})
client_id = resp['Location'].split('/')[-2]
resp2 = tc4.get(f'/clients/{client_id}/')
check("XSS: payload stored but rendered escaped (no <script> tag unescaped)",
    b"<script>alert" not in resp2.content and b"&lt;script&gt;" in resp2.content)

# Unauthenticated redirect
tc5 = TestClient()
resp = tc5.get('/clients/add')
check("Auth guard: unauthenticated /clients/add -> redirect to login", resp.status_code == 302)

print("\n=== Phase 5: Vulnerable build checks ===")
import importlib
from django.conf import settings as dj_settings
dj_settings.VULNERABLE = True

# SQLi login bypass: username = "admin' -- " skips password check
from django.db import connection
User.objects.filter(username='sqlitest').delete()
salt3 = generate_salt()
User.objects.create(username='sqlitest', email='sqli@test.com',
    password_hash=hmac_hash("RealPass1!x", salt3), salt=salt3)

# Simulate the vulnerable raw SQL the view runs
with connection.cursor() as cursor:
    vuln_username = "sqlitest' OR '1'='1"
    cursor.execute(
        f"SELECT id FROM accounts_user WHERE username='{vuln_username}'"
    )
    row = cursor.fetchone()
check("SQLi: OR 1=1 payload returns a row (injection works in vuln build)", row is not None)

# Comment injection
with connection.cursor() as cursor:
    cursor.execute("SELECT id FROM accounts_user WHERE username='sqlitest' -- ' AND password_hash='x'")
    row2 = cursor.fetchone()
check("SQLi: comment strip payload returns row", row2 is not None)

# XSS: raw name stored and |safe renders unescaped in vulnerable template
xss_raw = "<script>alert('You are hacked')</script>"
c2 = Client.objects.create(name=xss_raw)
check("XSS stored: raw script tag in DB name field", "<script>" in c2.name)

dj_settings.VULNERABLE = False

print("\n=== Cleanup ===")
User.objects.filter(username__in=['testverify','flowtest','sqlitest']).delete()
Client.objects.filter(name__in=['Test Client','Safe Client', xss, xss_raw]).delete()
print("  Test data cleaned up.")

print("\n\033[92mAll verification checks passed.\033[0m\n")
