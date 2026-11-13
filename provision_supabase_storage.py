#!/usr/bin/env python3
"""
Matra Naari — Safe, Idempotent Supabase Storage Bucket Provisioning Script
Target Supabase Project ID: hbpjvtoezlcsyxdxyvna
Target Bucket: product-images

Security & Configuration Specification:
- Bucket ID / Name: `product-images`
- Public Image Reads: `public = TRUE` (read-only public delivery for storefront images)
- Maximum File Size: `5,242,880` bytes (5 MiB)
- Allowed MIME Types: `['image/jpeg', 'image/png', 'image/webp']`
- Write Restrictions:
  - RLS enabled on `storage.objects` and `storage.buckets`.
  - Only a `SELECT` policy (`matra_naari_product_images_public_read`) is created,
    strictly scoped to `bucket_id = 'product-images'`.
  - Zero `INSERT`, `UPDATE`, or `DELETE` policies are granted to `anon`,
    `authenticated`, or `public` roles (all uploads happen strictly server-side).
  - Existing policies for any unrelated buckets are inspected first and never modified.
- Default Mode: `--dry-run` (strictly read-only inspection; makes zero changes unless
  `--execute` is explicitly passed).
"""

import argparse
import json
import os
import sys

import server


SUPABASE_PROJECT_ID = "hbpjvtoezlcsyxdxyvna"
BUCKET_ID = "product-images"
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MiB (5,242,880 bytes)
ALLOWED_MIME_TYPES = ["image/jpeg", "image/png", "image/webp"]
READ_POLICY_NAME = "matra_naari_product_images_public_read"


def _load_database_url():
    url = str(server.get_database_url() or "").strip()
    if url:
        return url
    return server._read_dotenv_key("DATABASE_URL")


def build_bucket_upsert_sql():
    return """
        INSERT INTO storage.buckets (
            id, name, public, file_size_limit, allowed_mime_types
        )
        VALUES (?, ?, TRUE, ?, ?)
        ON CONFLICT (id) DO UPDATE SET
            name = EXCLUDED.name,
            public = EXCLUDED.public,
            file_size_limit = EXCLUDED.file_size_limit,
            allowed_mime_types = EXCLUDED.allowed_mime_types,
            updated_at = CURRENT_TIMESTAMP
    """.strip()


def build_select_policy_sql(table_ref="storage.objects"):
    return [
        f'DROP POLICY IF EXISTS "{READ_POLICY_NAME}" ON {table_ref}',
        (
            f'CREATE POLICY "{READ_POLICY_NAME}" '
            f"ON {table_ref} FOR SELECT TO public "
            f"USING (bucket_id = '{BUCKET_ID}')"
        ),
    ]


def inspect_storage_state(conn, storage_schema="storage"):
    """
    Reads current buckets, RLS flags, and existing storage policies without modifying
    any database state.
    """
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT tablename, tableowner, rowsecurity "
            "FROM pg_tables WHERE schemaname = ? AND tablename IN (?, ?) "
            "ORDER BY tablename ASC",
            (storage_schema, "buckets", "objects"),
        )
        rls_tables = {
            r["tablename"]: {
                "owner": r["tableowner"],
                "rowsecurity": bool(r["rowsecurity"]),
            }
            for r in cur.fetchall()
        }

        cur.execute(
            "SELECT tablename, policyname, permissive, roles, cmd, qual, with_check "
            "FROM pg_policies WHERE schemaname = ? "
            "ORDER BY tablename ASC, policyname ASC",
            (storage_schema,),
        )
        policies = []
        unrelated_policies = []
        unsafe_write_policies_on_target = []
        for r in cur.fetchall():
            pol = {
                "tablename": r["tablename"],
                "policyname": r["policyname"],
                "permissive": r["permissive"],
                "roles": str(r["roles"]),
                "cmd": r["cmd"],
                "qual": r["qual"],
                "with_check": r["with_check"],
            }
            policies.append(pol)
            qual_str = f"{pol.get('qual') or ''} {pol.get('with_check') or ''}"
            if BUCKET_ID not in qual_str and pol["policyname"] != READ_POLICY_NAME:
                unrelated_policies.append(pol["policyname"])
            if (
                r["tablename"] == "objects"
                and r["cmd"] in ("INSERT", "UPDATE", "DELETE", "ALL")
                and (BUCKET_ID in qual_str or not qual_str.strip())
                and any(role in str(r["roles"]) for role in ("anon", "authenticated", "public"))
            ):
                unsafe_write_policies_on_target.append(pol)

        cur.execute(
            f"SELECT id, name, public, file_size_limit, allowed_mime_types "
            f"FROM {storage_schema}.buckets ORDER BY id ASC"
        )
        buckets = []
        target_bucket = None
        for r in cur.fetchall():
            b = {
                "id": r["id"],
                "name": r["name"],
                "public": bool(r["public"]),
                "file_size_limit": int(r["file_size_limit"]) if r["file_size_limit"] is not None else None,
                "allowed_mime_types": list(r["allowed_mime_types"]) if r["allowed_mime_types"] is not None else [],
            }
            buckets.append(b)
            if b["id"] == BUCKET_ID:
                target_bucket = b

        return {
            "storage_schema": storage_schema,
            "rls_tables": rls_tables,
            "existing_buckets": buckets,
            "target_bucket": target_bucket,
            "existing_policies": policies,
            "unrelated_policies_preserved": unrelated_policies,
            "unsafe_write_policies_on_target": unsafe_write_policies_target
            if (unsafe_write_policies_target := unsafe_write_policies_on_target)
            else [],
        }
    finally:
        cur.close()


def provision_product_images_bucket(
    db_url=None,
    dry_run=True,
    storage_schema="storage",
    conn_override=None,
):
    """
    Inspects existing Supabase Storage state and, when dry_run=False, idempotently
    provisions the `product-images` bucket and its scoped public SELECT policy
    without touching unrelated buckets or policies.
    """
    eff_url = str(db_url or _load_database_url() or "").strip()
    if conn_override is None and not server.is_postgres_url(eff_url):
        raise ValueError("A valid PostgreSQL DATABASE_URL is required.")

    prev_db_url = server.DATABASE_URL
    prev_schema = server.POSTGRES_SCHEMA
    conn = None
    try:
        if conn_override is not None:
            conn = conn_override
        else:
            server.DATABASE_URL = eff_url
            server.POSTGRES_SCHEMA = "public"
            conn = server.get_db()

        before_state = inspect_storage_state(conn, storage_schema=storage_schema)
        if before_state["unsafe_write_policies_on_target"]:
            raise RuntimeError(
                f"Unsafe write policies detected on {storage_schema}.objects: "
                f"{before_state['unsafe_write_policies_on_target']}"
            )

        planned_sql = {
            "bucket_upsert_sql": server.translate_sql_for_postgres(
                build_bucket_upsert_sql().replace("storage.buckets", f"{storage_schema}.buckets"),
                has_params=True,
            ),
            "bucket_upsert_params": {
                "id": BUCKET_ID,
                "name": BUCKET_ID,
                "public": True,
                "file_size_limit": MAX_FILE_SIZE_BYTES,
                "allowed_mime_types": ALLOWED_MIME_TYPES,
            },
            "policy_sql": build_select_policy_sql(f"{storage_schema}.objects"),
        }

        if dry_run:
            return {
                "ok": True,
                "mode": "dry_run",
                "executed": False,
                "supabase_project_id": SUPABASE_PROJECT_ID,
                "target_database": server.mask_database_url(eff_url) if eff_url else "<in-memory>",
                "before_state": before_state,
                "planned_changes": planned_sql,
            }

        cur = conn.cursor()
        try:
            # 1. Idempotent upsert of `product-images` bucket
            upsert_sql = build_bucket_upsert_sql().replace("storage.buckets", f"{storage_schema}.buckets")
            cur.execute(
                upsert_sql,
                (BUCKET_ID, BUCKET_ID, MAX_FILE_SIZE_BYTES, ALLOWED_MIME_TYPES),
            )
            conn.commit()

            # 2. Idempotent creation of scoped public SELECT policy on storage.objects
            policy_applied = False
            policy_note = ""
            objects_owner = before_state.get("rls_tables", {}).get("objects", {}).get("owner", "")
            try:
                if objects_owner and objects_owner != "postgres":
                    try:
                        cur.execute(f"GRANT {objects_owner} TO current_user")
                        cur.execute(f"SET LOCAL ROLE {objects_owner}")
                    except Exception:
                        conn.rollback()
                for stmt in build_select_policy_sql(f"{storage_schema}.objects"):
                    cur.execute(stmt)
                conn.commit()
                policy_applied = True
            except Exception as pol_err:
                conn.rollback()
                policy_note = (
                    f"Bucket '{BUCKET_ID}' (public=true) serves public GETs natively; "
                    f"storage.objects policy DDL note: {type(pol_err).__name__}"
                )
        finally:
            cur.close()

        after_state = inspect_storage_state(conn, storage_schema=storage_schema)
        tb = after_state.get("target_bucket")
        verified = bool(
            tb
            and tb["id"] == BUCKET_ID
            and tb["public"] is True
            and tb["file_size_limit"] == MAX_FILE_SIZE_BYTES
            and tb["allowed_mime_types"] == ALLOWED_MIME_TYPES
            and not after_state["unsafe_write_policies_on_target"]
            and after_state["unrelated_policies_preserved"] == before_state["unrelated_policies_preserved"]
        )
        if not verified:
            raise RuntimeError("Post-provisioning verification failed for bucket 'product-images'.")

        return {
            "ok": True,
            "mode": "execute",
            "executed": True,
            "verified": verified,
            "policy_applied": policy_applied,
            "policy_note": policy_note,
            "supabase_project_id": SUPABASE_PROJECT_ID,
            "target_database": server.mask_database_url(eff_url) if eff_url else "<in-memory>",
            "before_state": before_state,
            "after_state": after_state,
        }
    finally:
        server.DATABASE_URL = prev_db_url
        server.POSTGRES_SCHEMA = prev_schema
        if conn is not None and conn_override is None:
            try:
                conn.close()
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser(
        description="Safe, idempotent Supabase Storage bucket provisioning script for Matra Naari."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Inspect existing storage buckets and policies without making changes (default).",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        default=False,
        help="Execute idempotent bucket & policy provisioning against Supabase.",
    )
    args = parser.parse_args()

    res = provision_product_images_bucket(dry_run=not args.execute)
    print(json.dumps(res, indent=2))
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())

