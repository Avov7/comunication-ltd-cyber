# Comunication_LTD — Cybersecurity Final Project

HIT "Computer Security" course final project. A web application for a fictional ISP demonstrating secure development principles (Part A) and vulnerability exploitation + fixes (Part B).

**Tech stack:** Python 3.14 · Django 6.0 · MySQL 8.0

---

## Project overview

| Part | Description |
|---|---|
| Part A | Secure web app: Register, Login, Change Password, Forgot Password, Add Client |
| Part B | Same codebase in "vulnerable" mode: Stored XSS + SQLi demos, then fixed in secure mode |

---

## Prerequisites

- Python 3.9+ (tested on 3.14)
- MySQL 8.0 server running locally
- pip

---

## Installation

### 1. Clone / unzip the project

```bash
cd path/to/project
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Create the MySQL database

```sql
-- Run in MySQL as root
CREATE DATABASE IF NOT EXISTS comunication_ltd CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'comltd'@'localhost' IDENTIFIED BY 'Comltd2024!';
GRANT ALL PRIVILEGES ON comunication_ltd.* TO 'comltd'@'localhost';
FLUSH PRIVILEGES;
```

### 4. Configure environment

```bash
cp .env.example .env
# Edit .env if your DB credentials differ
```

### 5. Run migrations

```bash
python manage.py migrate
```

### 6. Start the server

```bash
python manage.py runserver
```

Open `http://localhost:8000/register` to begin.

---

## Switching between secure and vulnerable builds

**Secure build (default):**
```bash
python manage.py runserver
# or explicitly:
set DJANGO_SETTINGS_MODULE=comunication_ltd.settings.secure
python manage.py runserver
```

**Vulnerable build (Part B demo):**
```bash
set DJANGO_SETTINGS_MODULE=comunication_ltd.settings.vulnerable
python manage.py runserver
```

The `VULNERABLE` flag in settings switches:
- Raw f-string SQL ↔ Django ORM (parameterized queries)
- `{{ client.name|safe }}` ↔ `{{ client.name }}` (auto-escape)

---

## Application screens

| URL | Description |
|---|---|
| `/register` | Create a new account |
| `/login` | Log in |
| `/logout` | Log out |
| `/change-password` | Change password (login required) |
| `/forgot-password` | Request password reset token |
| `/reset-password` | Enter token + set new password |
| `/clients/add` | Add a new client (login required) |
| `/clients/<id>/` | View client detail |

---

## Password policy (`password_policy.json`)

| Rule | Value |
|---|---|
| Minimum length | 10 characters |
| Complexity | 3 of 4: uppercase, lowercase, digit, special character |
| Password history | Last 3 passwords blocked |
| Dictionary check | Common passwords rejected |
| Login lockout | 3 failed attempts → 30-minute lockout |

---

## Course concept → code mapping

| Course concept | Implementation |
|---|---|
| HMAC + Salt (password storage) | `accounts/security.py:hmac_hash` + `generate_salt` |
| SHA-2 recommended (course) | HMAC-SHA-256 used for password hashing |
| SHA-1 token (project spec) | `accounts/security.py:sha1_token` — forgot-password only |
| Parameterized queries (SQLi fix) | Django ORM in `accounts/views.py`, `clients/views.py` (secure branch) |
| HTML encoding (XSS fix) | Django auto-escape in `clients/templates/clients/client_detail.html` |
| Password policy | `password_policy.json` + `accounts/security.py:validate_complexity` |
| Password history | `accounts/models.py:PasswordHistory` + `accounts/security.py:check_history` |
| Account lockout | `accounts/models.py:User.locked_until` + lockout logic in `accounts/views.py:login_view` |

---

## Part B attack reproduction

See `attacks.md` for step-by-step instructions. Summary:

| Attack | Payload | Vulnerable location |
|---|---|---|
| Stored XSS | `<script>alert("You are hacked")</script>` in Name field | `clients/views.py` + template `\|safe` |
| SQLi login bypass | username: `admin' --` | `accounts/views.py` login f-string |
| SQLi OR bypass | username: `' OR '1'='1` | same |
| SQLi destructive | name: `'); DROP TABLE clients_client; --` | `clients/views.py` insert f-string |

---

## Running verification

```bash
python verify.py
```

Runs 25 automated checks across security module, models, HTTP flows, and vulnerability demos.

---

## Group Members

| Name | ID |
|---|---|
| אביב הלר | 207917600 |
| כרמל גרינטל | 207459876 |
| אסף ערוסי | 323108977 |
| אוראל פשרל | 207131251 |
| רוי בנימינוביץ | 322659376 |

---

## Project structure

```
comunication_ltd/
  settings/
    base.py          # shared settings
    secure.py        # VULNERABLE = False (default)
    vulnerable.py    # VULNERABLE = True
accounts/
  security.py        # HMAC-SHA-256, SHA-1 token, validators
  models.py          # User, PasswordHistory, PasswordResetToken
  views.py           # Register, Login, ChangePassword, ForgotPassword, ResetPassword
  urls.py
clients/
  models.py          # Client
  views.py           # AddClient, ClientDetail (secure/vulnerable branches)
  urls.py
templates/
  base.html
password_policy.json # Admin-editable policy
dictionary.txt       # Common passwords list
attacks.md           # Part B payloads + explanations
verify.py            # Automated verification
requirements.txt
.env.example
```
