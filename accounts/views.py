from django.shortcuts import render, redirect
from django.contrib import messages
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from django.db import connection
import datetime

from .models import User, PasswordHistory, PasswordResetToken
from .security import (
    generate_salt, hmac_hash, sha1_token,
    load_policy, validate_complexity, check_dictionary, check_history,
)

POLICY = load_policy(settings.PASSWORD_POLICY_PATH)


def _login_required(view_func):
    def wrapper(request, *args, **kwargs):
        if not request.session.get('user_id'):
            return redirect('/login')
        return view_func(request, *args, **kwargs)
    return wrapper


def register(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        password2 = request.POST.get('password2', '')
        errors = []

        if password != password2:
            errors.append("Passwords do not match.")

        ok, complexity_errors = validate_complexity(password, POLICY)
        errors.extend(complexity_errors)

        if POLICY.get('dictionary_check') and check_dictionary(password, settings.DICTIONARY_PATH):
            errors.append("Password is too common. Choose a stronger password.")

        if not errors:
            if getattr(settings, 'VULNERABLE', False):
                # VULNERABLE: raw SQL — injectable
                with connection.cursor() as cursor:
                    cursor.execute(
                        f"SELECT id FROM accounts_user WHERE username='{username}' OR email='{email}'"
                    )
                    if cursor.fetchone():
                        errors.append("Username or email already exists.")
            else:
                if User.objects.filter(username=username).exists() or User.objects.filter(email=email).exists():
                    errors.append("Username or email already exists.")

        if errors:
            return render(request, 'accounts/register.html', {
                'errors': errors,
                'username': username,
                'email': email,
            })

        salt = generate_salt()
        pwd_hash = hmac_hash(password, salt)
        user = User.objects.create(
            username=username,
            email=email,
            password_hash=pwd_hash,
            salt=salt,
        )
        PasswordHistory.objects.create(user=user, password_hash=pwd_hash, salt=salt)
        messages.success(request, "Registration successful. Please log in.")
        return redirect('/login')

    return render(request, 'accounts/register.html', {'errors': []})


def login_view(request):
    error = None
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')

        if getattr(settings, 'VULNERABLE', False):
            # VULNERABLE: auth done entirely in raw SQL — injectable
            # Bypass with: username = ' OR '1'='1' --
            with connection.cursor() as cursor:
                cursor.execute(
                    f"SELECT id, username FROM accounts_user "
                    f"WHERE username='{username}' AND password_hash != ''"
                )
                row = cursor.fetchone()
            if row:
                request.session['user_id'] = row[0]
                request.session['username'] = row[1]
                return redirect('/clients/add')
            else:
                error = "Invalid username or password."
        else:
            # SECURE: ORM lookup with parameterized queries
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                error = "Invalid username or password."
            else:
                if user.is_locked():
                    error = "Account locked due to too many failed attempts. Try again later."
                elif hmac_hash(password, bytes(user.salt)) != user.password_hash:
                    user.failed_attempts += 1
                    if user.failed_attempts >= POLICY['max_login_attempts']:
                        user.locked_until = timezone.now() + datetime.timedelta(
                            minutes=POLICY['lockout_minutes']
                        )
                        user.save(update_fields=['failed_attempts', 'locked_until'])
                        error = "Account locked due to too many failed attempts. Try again later."
                    else:
                        user.save(update_fields=['failed_attempts', 'locked_until'])
                        error = "Invalid username or password."
                else:
                    user.failed_attempts = 0
                    user.locked_until = None
                    user.save(update_fields=['failed_attempts', 'locked_until'])
                    request.session['user_id'] = user.id
                    request.session['username'] = user.username
                    return redirect('/clients/add')

    return render(request, 'accounts/login.html', {'error': error})


@_login_required
def change_password(request):
    errors = []
    if request.method == 'POST':
        current_password = request.POST.get('current_password', '')
        new_password = request.POST.get('new_password', '')
        new_password2 = request.POST.get('new_password2', '')

        user = User.objects.get(id=request.session['user_id'])
        if hmac_hash(current_password, bytes(user.salt)) != user.password_hash:
            errors.append("Current password is incorrect.")

        if new_password != new_password2:
            errors.append("New passwords do not match.")

        ok, complexity_errors = validate_complexity(new_password, POLICY)
        errors.extend(complexity_errors)

        if POLICY.get('dictionary_check') and check_dictionary(new_password, settings.DICTIONARY_PATH):
            errors.append("Password is too common. Choose a stronger password.")

        if not errors:
            history = user.password_history.all()[:POLICY['history_count']]
            history_pairs = [(h.password_hash, bytes(h.salt)) for h in history]
            if check_history(new_password, history_pairs):
                errors.append(f"Password was used recently. Choose a different password.")

        if not errors:
            new_salt = generate_salt()
            new_hash = hmac_hash(new_password, new_salt)
            user.password_hash = new_hash
            user.salt = new_salt
            user.save(update_fields=['password_hash', 'salt'])
            PasswordHistory.objects.create(user=user, password_hash=new_hash, salt=new_salt)
            # Keep only last N history entries
            old_entries = user.password_history.all()[POLICY['history_count']:]
            for entry in old_entries:
                entry.delete()
            messages.success(request, "Password changed successfully.")
            return redirect('/clients/add')

    return render(request, 'accounts/change_password.html', {'errors': errors})


def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            messages.success(request, "If that email is registered, a reset token has been sent.")
            return redirect('/forgot-password')

        token = sha1_token()
        expires = timezone.now() + datetime.timedelta(hours=1)
        PasswordResetToken.objects.create(user=user, token_sha1=token, expires_at=expires)

        send_mail(
            subject="Password Reset Token - Comunication LTD",
            message=f"Your reset token is: {token}\n\nEnter it at /reset-password",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
        )
        messages.success(request, "If that email is registered, a reset token has been sent.")
        return redirect('/reset-password')

    return render(request, 'accounts/forgot_password.html', {})


def reset_password(request):
    errors = []
    if request.method == 'POST':
        token_input = request.POST.get('token', '').strip()
        new_password = request.POST.get('new_password', '')
        new_password2 = request.POST.get('new_password2', '')

        try:
            token_obj = PasswordResetToken.objects.get(
                token_sha1=token_input,
                used=False,
                expires_at__gt=timezone.now(),
            )
        except PasswordResetToken.DoesNotExist:
            errors.append("Invalid or expired reset token.")
            return render(request, 'accounts/reset_password.html', {'errors': errors})

        if new_password != new_password2:
            errors.append("Passwords do not match.")

        ok, complexity_errors = validate_complexity(new_password, POLICY)
        errors.extend(complexity_errors)

        if not errors:
            user = token_obj.user
            new_salt = generate_salt()
            new_hash = hmac_hash(new_password, new_salt)
            user.password_hash = new_hash
            user.salt = new_salt
            user.save(update_fields=['password_hash', 'salt'])
            PasswordHistory.objects.create(user=user, password_hash=new_hash, salt=new_salt)
            token_obj.used = True
            token_obj.save(update_fields=['used'])
            messages.success(request, "Password reset successfully. Please log in.")
            return redirect('/login')

    return render(request, 'accounts/reset_password.html', {'errors': errors})


def logout_view(request):
    request.session.flush()
    return redirect('/login')
