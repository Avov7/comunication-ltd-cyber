import hmac
import hashlib
import os
import json
from pathlib import Path


def generate_salt() -> bytes:
    return os.urandom(16)


def hmac_hash(password: str, salt: bytes) -> str:
    """HMAC-SHA-256 password hash. Course-required: HMAC + Salt."""
    return hmac.new(salt, password.encode('utf-8'), hashlib.sha256).hexdigest()


def sha1_token() -> str:
    """SHA-1 of random bytes — used only for forgot-password token per project spec."""
    return hashlib.sha1(os.urandom(32)).hexdigest()


def load_policy(policy_path: Path) -> dict:
    with open(policy_path, 'r') as f:
        return json.load(f)


def validate_complexity(password: str, policy: dict) -> tuple[bool, list[str]]:
    errors = []
    if len(password) < policy['min_length']:
        errors.append(f"Password must be at least {policy['min_length']} characters.")

    classes_met = 0
    if any(c.isupper() for c in password):
        classes_met += 1
    if any(c.islower() for c in password):
        classes_met += 1
    if any(c.isdigit() for c in password):
        classes_met += 1
    if any(not c.isalnum() for c in password):
        classes_met += 1

    required = policy.get('complexity_classes_required', 3)
    if classes_met < required:
        errors.append(
            f"Password must contain at least {required} of: uppercase, lowercase, digit, special character."
        )

    return (len(errors) == 0, errors)


def check_dictionary(password: str, dict_path: Path) -> bool:
    """Returns True if password is based on a dictionary word (should be rejected).
    Catches exact matches and common variants like 'password123!' or 'Password1'."""
    import re
    try:
        with open(dict_path, 'r') as f:
            banned = {line.strip().lower() for line in f if line.strip()}
        pwd_lower = password.lower()
        if pwd_lower in banned:
            return True
        # Strip trailing digits and special characters to catch variants like 'password123!'
        base = re.sub(r'[\d\W_]+$', '', pwd_lower)
        if base and base in banned:
            return True
        return False
    except FileNotFoundError:
        return False


def check_history(password: str, history_hashes: list[tuple[str, bytes]]) -> bool:
    """Returns True if password matches any previous hash (should be rejected).
    history_hashes: list of (hash_hex, salt_bytes) tuples."""
    for prev_hash, prev_salt in history_hashes:
        if hmac_hash(password, prev_salt) == prev_hash:
            return True
    return False
