#!/usr/bin/env python3
"""
Matra Naari — Secure Local .env Configuration for Supabase PostgreSQL
Supabase Project ID: hbpjvtoezlcsyxdxyvna
Session Pooler Host: aws-0-ap-south-1.pooler.supabase.com:5432

- Prompts for the database password using getpass (hidden terminal input; never echoed).
- URL-encodes all special characters in the password via urllib.parse.quote(pw, safe="").
- Enforces sslmode=require on the Session Pooler URL.
- Writes DATABASE_URL to the gitignored .env file with 0600 permissions, preserving any
  other existing environment variables in .env.
- Never prints or logs the password or unmasked connection string.
"""

import getpass
import os
import sys
import urllib.parse

import server

SUPABASE_PROJECT_ID = "hbpjvtoezlcsyxdxyvna"
SESSION_POOLER_HOST = "aws-0-ap-south-1.pooler.supabase.com"
SESSION_POOLER_PORT = 5432
SUPABASE_DB_USER = f"postgres.{SUPABASE_PROJECT_ID}"
SUPABASE_DB_NAME = "postgres"


def build_session_pooler_url(raw_password):
    clean_pw = str(raw_password or "").strip()
    if not clean_pw:
        raise ValueError("Database password cannot be empty.")
    encoded_pw = urllib.parse.quote(clean_pw, safe="")
    return (
        f"postgresql://{SUPABASE_DB_USER}:{encoded_pw}"
        f"@{SESSION_POOLER_HOST}:{SESSION_POOLER_PORT}/{SUPABASE_DB_NAME}?sslmode=require"
    )


def save_database_url_to_dotenv(db_url, dotenv_path=None):
    target_path = dotenv_path or os.path.join(server.BASE_DIR, ".env")
    existing_lines = []
    if os.path.isfile(target_path):
        with open(target_path, "r", encoding="utf-8") as f:
            existing_lines = f.read().splitlines()

    updated_lines = []
    replaced = False
    for line in existing_lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            k, _ = stripped.split("=", 1)
            if k.strip() == "DATABASE_URL":
                if not replaced:
                    updated_lines.append(f'DATABASE_URL="{db_url}"')
                    replaced = True
                continue
        updated_lines.append(line)

    if not replaced:
        updated_lines.append(f'DATABASE_URL="{db_url}"')

    fd = os.open(target_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out_f:
        out_f.write("\n".join(updated_lines) + "\n")
    try:
        os.chmod(target_path, 0o600)
    except Exception:
        pass
    return target_path


def main():
    print("=" * 68)
    print(" Matra Naari — Secure Supabase Session Pooler Setup (.env)")
    print(f" Project ID : {SUPABASE_PROJECT_ID}")
    print(f" Pooler Host: {SESSION_POOLER_HOST}:{SESSION_POOLER_PORT} (sslmode=require)")
    print("=" * 68)

    try:
        raw_pw = getpass.getpass(
            f"Enter Supabase database password for {SUPABASE_DB_USER} (input hidden): "
        )
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled. No changes written to .env.")
        return 1

    if not raw_pw or not raw_pw.strip():
        print("Error: Password was empty. No changes written to .env.")
        return 1

    # If the user pasted a full postgresql:// URL by mistake, extract its password safely
    inp = raw_pw.strip()
    if inp.lower().startswith(("postgres://", "postgresql://")):
        parsed = urllib.parse.urlsplit(inp)
        extracted_pw = urllib.parse.unquote(parsed.password or "")
        if not extracted_pw:
            print("Error: Could not extract password from URL.")
            return 1
        db_url = build_session_pooler_url(extracted_pw)
    else:
        db_url = build_session_pooler_url(inp)

    dotenv_path = save_database_url_to_dotenv(db_url)
    print(f"\n[OK] Saved DATABASE_URL to gitignored {os.path.basename(dotenv_path)} (mode 0600).")
    print(f"[OK] Masked URL: {server.mask_database_url(db_url)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

