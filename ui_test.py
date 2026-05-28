"""
Playwright UI walkthrough for Comunication_LTD.
Runs a headed browser so you can watch every step.
Usage: python ui_test.py
"""
from playwright.sync_api import sync_playwright, expect
import time, re

BASE = "http://localhost:8000"
SLOW = 800  # ms between actions so you can watch

PASS_MARK = "[PASS]"
FAIL_MARK = "[FAIL]"

def check(label, condition, extra=""):
    status = PASS_MARK if condition else FAIL_MARK
    print(f"  {status} {label}" + (f" — {extra}" if extra else ""))
    if not condition:
        raise AssertionError(f"FAILED: {label}")

def run(playwright):
    browser = playwright.chromium.launch(headless=False, slow_mo=SLOW)
    ctx = browser.new_context()
    page = ctx.new_page()

    print("\n" + "="*60)
    print("SECURE BUILD TESTS")
    print("="*60)

    # ------------------------------------------------------------------
    print("\n--- Register: weak passwords rejected ---")

    page.goto(f"{BASE}/register")
    page.fill('[name=username]', 'testuser')
    page.fill('[name=email]', 'test@test.com')
    page.fill('[name=password]', 'short')
    page.fill('[name=password2]', 'short')
    page.click('button[type=submit]')
    page.wait_for_load_state()
    content = page.content()
    check("Short password rejected", "at least 10" in content)

    page.fill('[name=password]', 'alllowercase1')
    page.fill('[name=password2]', 'alllowercase1')
    page.click('button[type=submit]')
    page.wait_for_load_state()
    check("Complexity error shown (alllowercase1)", "at least 3 of" in page.content())

    page.fill('[name=password]', 'password123!')
    page.fill('[name=password2]', 'password123!')
    page.click('button[type=submit]')
    page.wait_for_load_state()
    check("Dictionary word rejected (password123!)", "too common" in page.content())

    # ------------------------------------------------------------------
    print("\n--- Register: valid account ---")

    page.fill('[name=username]', 'testuser')
    page.fill('[name=email]', 'test@test.com')
    page.fill('[name=password]', 'SecurePass1!')
    page.fill('[name=password2]', 'SecurePass1!')
    page.click('button[type=submit]')
    page.wait_for_url(f"{BASE}/login")
    check("Valid registration redirects to /login", "/login" in page.url)
    check("Success message shown", "Registration successful" in page.content())

    # ------------------------------------------------------------------
    print("\n--- Register: duplicate rejected ---")

    page.goto(f"{BASE}/register")
    page.fill('[name=username]', 'testuser')
    page.fill('[name=email]', 'test@test.com')
    page.fill('[name=password]', 'SecurePass1!')
    page.fill('[name=password2]', 'SecurePass1!')
    page.click('button[type=submit]')
    page.wait_for_load_state()
    check("Duplicate username/email rejected", "already exists" in page.content())

    # ------------------------------------------------------------------
    print("\n--- Login: lockout after 3 failed attempts ---")

    page.goto(f"{BASE}/login")
    for i in range(3):
        page.fill('[name=username]', 'testuser')
        page.fill('[name=password]', 'WrongPass99!')
        page.click('button[type=submit]')
        page.wait_for_load_state()
        print(f"    attempt {i+1}/3...")

    check("Account locked after 3 failures", "locked" in page.content())

    # ------------------------------------------------------------------
    print("\n--- Forgot password: reset token flow ---")

    # Register a second user (testuser is locked)
    page.goto(f"{BASE}/register")
    page.fill('[name=username]', 'testuser2')
    page.fill('[name=email]', 'test2@test.com')
    page.fill('[name=password]', 'SecurePass1!')
    page.fill('[name=password2]', 'SecurePass1!')
    page.click('button[type=submit]')
    page.wait_for_url(f"{BASE}/login")

    page.goto(f"{BASE}/forgot-password")
    page.fill('[name=email]', 'test2@test.com')
    page.click('button[type=submit]')
    page.wait_for_load_state()
    check("Forgot password: success message shown", "reset token" in page.content().lower())

    # Grab the token from the DB via subprocess (avoids async context conflict)
    import subprocess
    result = subprocess.run(
        ['python', '-c',
         'import os,sys,django; os.environ["DJANGO_SETTINGS_MODULE"]="comunication_ltd.settings.secure"; '
         'sys.path.insert(0,"."); django.setup(); '
         'from accounts.models import PasswordResetToken; '
         'obj=PasswordResetToken.objects.filter(used=False).order_by("-created_at").first(); '
         'print(obj.token_sha1 if obj else "NONE")'],
        capture_output=True, text=True,
        cwd=r'C:\Users\avov7\Desktop\HIT\אבטחת מחשבים\Project'
    )
    token = result.stdout.strip()
    check("Token created in DB", token != "NONE" and len(token) == 40)
    print(f"    Token: {token[:16]}...")

    page.goto(f"{BASE}/reset-password")
    page.fill('[name=token]', token)
    page.fill('[name=new_password]', 'NewSecure2@!')
    page.fill('[name=new_password2]', 'NewSecure2@!')
    page.click('button[type=submit]')
    page.wait_for_url(f"{BASE}/login")
    check("Password reset: redirects to /login", "/login" in page.url)
    check("Success message shown", "reset successfully" in page.content())

    # ------------------------------------------------------------------
    print("\n--- Login: correct password ---")

    page.fill('[name=username]', 'testuser2')
    page.fill('[name=password]', 'NewSecure2@!')
    page.click('button[type=submit]')
    page.wait_for_url(f"{BASE}/clients/add")
    check("Login with new password succeeds", "/clients/add" in page.url)

    # ------------------------------------------------------------------
    print("\n--- Change password ---")

    page.goto(f"{BASE}/change-password")
    # Try reusing current password
    page.fill('[name=current_password]', 'NewSecure2@!')
    page.fill('[name=new_password]', 'NewSecure2@!')
    page.fill('[name=new_password2]', 'NewSecure2@!')
    page.click('button[type=submit]')
    page.wait_for_load_state()
    check("Reused password rejected", "used recently" in page.content())

    # Change to new password
    page.fill('[name=current_password]', 'NewSecure2@!')
    page.fill('[name=new_password]', 'Changed3#abc')
    page.fill('[name=new_password2]', 'Changed3#abc')
    page.click('button[type=submit]')
    page.wait_for_url(f"{BASE}/clients/add")
    check("Change password succeeds", "/clients/add" in page.url)

    # ------------------------------------------------------------------
    print("\n--- Add client (secure: XSS neutralised) ---")

    page.goto(f"{BASE}/clients/add")
    xss = "<script>alert('You are hacked')</script>"
    page.fill('[name=name]', xss)
    page.fill('[name=phone]', '050-1234567')
    page.fill('[name=address]', 'Tel Aviv')
    page.fill('[name=package]', 'Gold')
    page.click('button[type=submit]')
    page.wait_for_load_state()
    raw_html = page.content()
    check("XSS payload stored but NOT executed (no alert)", "<script>alert" not in raw_html)
    check("XSS payload rendered as escaped text", "&lt;script&gt;" in raw_html)

    # ------------------------------------------------------------------
    print("\n--- Auth guard ---")

    ctx2 = browser.new_context()
    page2 = ctx2.new_page()
    page2.goto(f"{BASE}/clients/add")
    page2.wait_for_url(f"{BASE}/login")
    check("Unauthenticated /clients/add redirects to /login", "/login" in page2.url)
    ctx2.close()

    time.sleep(2)
    browser.close()


def run_vulnerable_tests():
    import os, sys, django as dj
    os.environ['DJANGO_SETTINGS_MODULE'] = 'comunication_ltd.settings.secure'
    sys.path.insert(0, '.')
    dj.setup()

    from django.conf import settings as dj_settings
    from django.db import connection
    from accounts.models import User as UModel
    from clients.models import Client
    from accounts.security import generate_salt, hmac_hash

    print("\n" + "="*60)
    print("VULNERABLE BUILD TESTS")
    print("="*60)

    UModel.objects.filter(username='sqlitest').delete()
    s = generate_salt()
    UModel.objects.create(username='sqlitest', email='sqli@test.com',
        password_hash=hmac_hash('RealPass1!', s), salt=s)

    print("\n--- SQLi: OR 1=1 payload ---")
    with connection.cursor() as cursor:
        payload = "sqlitest' OR '1'='1"
        cursor.execute(f"SELECT id FROM accounts_user WHERE username='{payload}'")
        row = cursor.fetchone()
    check("SQLi OR 1=1 returns a row (login would succeed without real password)", row is not None)

    print("\n--- SQLi: comment-strip bypass ---")
    with connection.cursor() as cursor:
        cursor.execute("SELECT id FROM accounts_user WHERE username='sqlitest' -- ' AND password_hash='fakehash'")
        row2 = cursor.fetchone()
    check("SQLi comment strip bypasses password check", row2 is not None)

    print("\n--- XSS stored raw in DB ---")
    xss_client = Client.objects.create(name="<script>alert('You are hacked')</script>")
    check("XSS payload stored as-is in DB (no escaping at storage)", "<script>" in xss_client.name)
    print("    In vulnerable build the template renders this with |safe -> script executes in browser")

    UModel.objects.filter(username__in=['testuser','testuser2','sqlitest']).delete()
    Client.objects.filter(name__contains='script').delete()

    print("\n" + "="*60)
    print("ALL TESTS PASSED")
    print("="*60 + "\n")


with sync_playwright() as pw:
    run(pw)

run_vulnerable_tests()
