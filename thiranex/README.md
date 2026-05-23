# Password Strength Analyzer

A simple Python tool to evaluate password strength, suggest stronger passwords, and optionally store password history in a SQLite database to prevent reuse.

## Features

- Checks password length, character complexity, and uniqueness
- Flags common passwords and repeated patterns
- Provides strength classification: `Very Strong`, `Strong`, `Moderate`, `Weak`
- Generates suggested strong passwords
- Optional SQLite integration to prevent reuse of old passwords

## Usage

```bash
python password_strength_analyzer.py
```

Or analyze a password directly:

```bash
python password_strength_analyzer.py "MyP@ssw0rd123"
```

To enable password history reuse prevention:

```bash
python password_strength_analyzer.py "MyP@ssw0rd123" --db password_history.db
```

## Options

- `--db <file>`: SQLite database path for password history
- `--suggestions <n>`: Number of suggested strong passwords to generate
- `--length <n>`: Minimum length for generated password suggestions

## Requirements

- Python 3.8+

## Notes

- The tool uses a basic common-password blacklist and password hashing for history tracking.
- For production use, integrate with a secure secrets manager and store password hashes with a stronger KDF.
