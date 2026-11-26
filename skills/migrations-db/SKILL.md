---
name: migrations-db
version: "2"
description: Zero-downtime database migration and rollback safety skill for SQL DDL, table locks, backward compatibility, and paired down-scripts.
tags: [sql, migrations, database, rollback]
paths: ["*.sql", "migrations/*", "db/*"]
tools: [get_pr_diff, read_file, list_files, search_code]
---

Audit SQL migrations and schema changes for **production table locks, data loss, and unsafe rollbacks**.

## 1. Expand-Contract & Lock Checklist
- **Destructive DDL (`critical`):** `DROP TABLE`, `DROP COLUMN`, or `TRUNCATE TABLE` deployed in the same release as application code breaks rolling deploys and causes irreversible data loss on rollback.
- **Exclusive Table Locks (`warning`):** `CREATE INDEX` without `CONCURRENTLY` (PostgreSQL), `ALTER COLUMN ... TYPE` full-table rewrites, or `ADD COLUMN ... NOT NULL` without a `DEFAULT`.
- **Rollback Readiness (`warning`):** `.up.sql` migrations missing a paired `.down.sql` rollback script (or irreversible data transformations without backfill safety).
- **Application Code Safety (`warning`):** Schema changes that break older running replicas (e.g., renaming a column still queried during zero-downtime rollout).

## 2. Noise Suppression
- Do not flag `CREATE INDEX CONCURRENTLY`, `ADD COLUMN ... NOT NULL DEFAULT ...`, or `.up.sql` files that include a valid `.down.sql` companion.
