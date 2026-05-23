import argparse
import os
import re
import secrets
import sqlite3
import string
import sys
from hashlib import sha256

COMMON_PASSWORDS = {
    "123456",
    "password",
    "123456789",
    "qwerty",
    "abc123",
    "111111",
    "letmein",
    "welcome",
    "monkey",
    "dragon",
}

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS password_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    password_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


def load_database(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.execute(DB_SCHEMA)
    conn.commit()
    return conn


def hash_password(password: str) -> str:
    return sha256(password.encode("utf-8")).hexdigest()


def analyze_password(password: str, history_hashes=None):
    if history_hashes is None:
        history_hashes = set()

    length = len(password)
    categories = {
        "lower": bool(re.search(r"[a-z]", password)),
        "upper": bool(re.search(r"[A-Z]", password)),
        "digit": bool(re.search(r"[0-9]", password)),
        "symbol": bool(re.search(r"[^A-Za-z0-9]", password)),
    }
    category_count = sum(categories.values())

    unique_chars = len(set(password))
    entropy_score = min(4, category_count) + (length / 8) + (unique_chars / 8)

    issues = []
    if length < 8:
        issues.append("Password is too short. Use at least 8 characters.")
    elif length < 12:
        issues.append("Consider increasing length to 12+ characters.")

    if category_count < 3:
        issues.append("Include uppercase, lowercase, digits, and symbols for better complexity.")
    if password.lower() in COMMON_PASSWORDS:
        issues.append("This password is too common and easily guessed.")
    if unique_chars < max(4, length // 2):
        issues.append("Use more unique characters to reduce repetition.")
    if hash_password(password) in history_hashes:
        issues.append("This password was used before. Choose a new password.")

    if entropy_score >= 9 and not issues:
        strength = "Very Strong"
    elif entropy_score >= 7:
        strength = "Strong"
    elif entropy_score >= 5:
        strength = "Moderate"
    else:
        strength = "Weak"

    return {
        "password": password,
        "length": length,
        "categories": categories,
        "unique_chars": unique_chars,
        "entropy_score": round(entropy_score, 2),
        "strength": strength,
        "issues": issues,
    }


def suggest_passwords(count=3, min_length=16):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    suggestions = []
    for _ in range(count):
        password = "".join(secrets.choice(alphabet) for _ in range(min_length))
        suggestions.append(password)
    return suggestions


def display_analysis(result):
    print("\nPassword Strength Analysis")
    print("---------------------------")
    print(f"Strength: {result['strength']}")
    print(f"Length: {result['length']}")
    print(f"Categories: {sum(result['categories'].values())}/4")
    print(f"Unique characters: {result['unique_chars']}")
    print(f"Entropy score: {result['entropy_score']}")
    if result["issues"]:
        print("\nSuggestions:")
        for issue in result["issues"]:
            print(f"- {issue}")
    else:
        print("No issues found: your password is strong.")


def save_password(conn, password: str):
    password_hash = hash_password(password)
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO password_history (password_hash) VALUES (?)",
            (password_hash,),
        )


def get_history_hashes(conn):
    cursor = conn.execute("SELECT password_hash FROM password_history")
    return {row[0] for row in cursor.fetchall()}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Password Strength Analyzer: evaluate password strength, suggest improvements, and optionally block reuse of old passwords."
    )
    parser.add_argument(
        "password",
        nargs="?",
        help="Password to analyze. If omitted, you will be prompted interactively.",
    )
    parser.add_argument(
        "--db",
        dest="db_path",
        default=None,
        help="Optional SQLite database file to store password history and prevent reuse.",
    )
    parser.add_argument(
        "--suggestions",
        type=int,
        default=3,
        help="Number of suggested strong passwords to generate when a password is weak. Default: 3.",
    )
    parser.add_argument(
        "--length",
        type=int,
        default=16,
        help="Minimum length for suggested passwords. Default: 16.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    password = args.password
    if not password:
        try:
            password = input("Enter password to analyze: ")
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
            sys.exit(1)

    conn = None
    history_hashes = set()
    if args.db_path:
        conn = load_database(args.db_path)
        history_hashes = get_history_hashes(conn)

    analysis = analyze_password(password, history_hashes)
    display_analysis(analysis)

    if analysis["issues"]:
        print("\nRecommended strong passwords:")
        for suggestion in suggest_passwords(count=args.suggestions, min_length=args.length):
            print(f"- {suggestion}")

    if conn is not None:
        save_password(conn, password)
        print(f"\nPassword hash saved to history database: {args.db_path}")


if __name__ == "__main__":
    main()
