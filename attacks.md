# Part B — Attack Demonstrations

All payloads below were taught in the HIT cybersecurity course (SSDLC presentation + lesson transcripts).

---

## How to switch builds

```bash
# Vulnerable build
set DJANGO_SETTINGS_MODULE=comunication_ltd.settings.vulnerable
python manage.py runserver

# Secure build (default)
set DJANGO_SETTINGS_MODULE=comunication_ltd.settings.secure
python manage.py runserver
```

---

## Attack 1 — Stored XSS (Part A item 4: Add Client)

**Target:** The "Name" field on Add Client. The name is displayed back on the Client Detail page.

### Payload (cookie stealer — use this for demo)
```
<script>alert(document.cookie)</script>
```

### Payload (simple proof-of-concept)
```
<script>alert("You are hacked")</script>
```

### How to reproduce (vulnerable build)
1. Start the **vulnerable** build
2. Log in and go to `/clients/add`
3. Enter the payload in the **Name** field, submit
4. You are redirected to the Client Detail page
5. The script executes — alert box fires / page redirects to attacker URL

### Why it works (vulnerable build)
The template renders `{{ client.name|safe }}` — Django's `|safe` filter disables auto-escaping, so the raw `<script>` tag is injected into the HTML as-is.

```html
<!-- vulnerable template (clients/templates/clients/client_detail.html) -->
<p>Name: {{ client.name|safe }}</p>
```

### Fix (secure build)
Remove the `|safe` filter. Django's **auto-escape** is on by default — equivalent to C#'s `Server.HtmlEncode` taught in the course.

```html
<!-- secure template -->
<p>Name: {{ client.name }}</p>
```

Django escapes `<` → `&lt;`, `>` → `&gt;`, so the browser sees text, not a script tag.

---

## Attack 2 — SQL Injection on Login (Part A item 3)

**Target:** The username field on the Login page.

### Payload 1 — OR always-true (no account needed)
```
username: ' OR '1'='1'#
password: anything
```

### Payload 2 — comment strip (logs in as existing user)
```
username: admin'#
password: anything
```

### How to reproduce (vulnerable build)
1. Start the **vulnerable** build
2. Go to `/login`
3. Enter either payload as username, any string as password
4. Login succeeds without knowing any real password

### Why it works (vulnerable build)
The view builds SQL by string formatting:
```python
# accounts/views.py — vulnerable login branch
cursor.execute(
    f"SELECT id, username FROM accounts_user "
    f"WHERE username='{username}' AND password_hash != ''"
)
```
With `' OR '1'='1'#` the executed query becomes:
```sql
SELECT ... FROM accounts_user WHERE username='' OR '1'='1'#' AND password_hash != ''
```
The `OR '1'='1'` makes the WHERE clause always true, returning all users. The `#` comments out the rest. Login succeeds without a valid password.

### Fix (secure build)
Use **parameterized queries** (Django ORM):
```python
# secure login branch
user = User.objects.get(username=username)
```
The ORM uses `cursor.execute(sql, [params])` internally — equivalent to C#'s `Parameters.AddWithValue` taught in the course. User input is never concatenated into SQL.

---

## Attack 3 — SQL Injection on Register (Part A item 1)

**Target:** Username field on the Register page.

### Payload — bypass duplicate-user check
```
username: ' AND '1'='2'#
email:    any valid email (e.g. test@test.com)
password: any valid password
```

### How to reproduce (vulnerable build)
1. Start the **vulnerable** build
2. Register a normal account (e.g. username `alice`, email `alice@test.com`)
3. Try registering again with the same username — normally blocked with "Username or email already exists"
4. Now register again with username `' AND '1'='2' -- ` and email `alice@test.com`
5. Registration succeeds — a duplicate account is created despite `alice` already existing

### Why it works
The vulnerable view checks for existing users with a raw f-string SELECT:
```python
cursor.execute(
    f"SELECT id FROM accounts_user WHERE username='{username}' OR email='{email}'"
)
```
With the payload the query becomes:
```sql
SELECT id FROM accounts_user WHERE username='' AND '1'='2'#' OR email='alice@test.com'
```
`'1'='2'` is always false, and `#` comments out the `OR email=...` clause. The WHERE is always false — no existing user is ever found — so the duplicate check is bypassed and the INSERT proceeds.

### Fix (secure build)
Django ORM `User.objects.filter(username=username).exists()` — parameterized, input treated as data not SQL.

---

## Attack 4 — SQL Injection on Add Client / System Screen (Part A item 4)

**Target:** Name field on Add Client.

### Payload — drop table
```
name: '); DROP TABLE clients_client; --
```

### How to reproduce (vulnerable build)
1. Start the **vulnerable** build
2. Go to `/clients/add`
3. Enter the payload in the Name field
4. The INSERT statement breaks; with certain MySQL configs the DROP executes

### Why it works
Same root cause as Attack 3 — name is concatenated directly into the INSERT SQL:
```python
cursor.execute(
    f"INSERT INTO clients_client (name, ...) VALUES ('{name}', ...)"
)
```

### Fix (secure build)
Django ORM `Client.objects.create(name=name, ...)` — parameterized, name treated as data not SQL.

---

## Side-by-side diff summary (all attacks)

| Location | Vulnerable | Secure |
|---|---|---|
| `accounts/views.py` login | `f"SELECT ... WHERE username='{username}'"` | `User.objects.get(username=username)` |
| `accounts/views.py` register | `f"SELECT ... WHERE username='{username}'"` | `User.objects.filter(username=username).exists()` |
| `clients/views.py` add | `f"INSERT INTO ... VALUES ('{name}', ...)"` | `Client.objects.create(name=name, ...)` |
| `clients/templates/client_detail.html` | `{{ client.name\|safe }}` | `{{ client.name }}` |
