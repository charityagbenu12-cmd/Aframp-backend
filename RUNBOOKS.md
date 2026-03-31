# Database Runbooks

Operational procedures for database backup, restoration, and point-in-time
recovery. Keep this document up to date whenever the backup strategy changes.

---

## Table of Contents

1. [Restore from a Daily Snapshot](#1-restore-from-a-daily-snapshot)
2. [Point-in-Time Recovery (PITR) via WAL Archives](#2-point-in-time-recovery-pitr-via-wal-archives)
3. [Verify a Restored Database Before Promoting to Production](#3-verify-a-restored-database-before-promoting-to-production)
4. [Recovery Time Objectives](#4-recovery-time-objectives)
5. [Restoration Drill Log](#5-restoration-drill-log)

---

## 1. Restore from a Daily Snapshot

### Prerequisites
- AWS CLI configured with credentials that have `s3:GetObject` on the backup
  bucket.
- `BACKUP_ENCRYPTION_KEY` available (stored in the team password manager).
- A target PostgreSQL 16 instance (can be a fresh RDS instance or local
  Docker container).

### Steps

```bash
# 1. List available snapshots (most recent last)
aws s3 ls s3://<BACKUP_BUCKET>/snapshots/ | sort

# 2. Download the desired snapshot
SNAPSHOT="snapshot_20260327T020000Z.sql.gz.enc"
aws s3 cp "s3://<BACKUP_BUCKET>/snapshots/${SNAPSHOT}" /tmp/${SNAPSHOT}

# 3. Decrypt and decompress
openssl enc -d -aes-256-cbc -pbkdf2 \
  -pass pass:"${BACKUP_ENCRYPTION_KEY}" \
  -in /tmp/${SNAPSHOT} \
  | gunzip > /tmp/restore.sql

# 4. Create a target database
createdb -h <TARGET_HOST> -U postgres aframp_restore

# 5. Restore
psql -h <TARGET_HOST> -U postgres aframp_restore < /tmp/restore.sql

# 6. Clean up plaintext dump
rm -f /tmp/restore.sql /tmp/${SNAPSHOT}
```

### Expected duration
Approximately **15–30 minutes** for a database up to 50 GB, depending on
network bandwidth and target instance I/O.

---

## 2. Point-in-Time Recovery (PITR) via WAL Archives

Use PITR when you need to recover to a specific timestamp (e.g. just before an
accidental bulk delete).

### Prerequisites
- A base snapshot that predates the target recovery timestamp.
- WAL segments covering the gap between the snapshot and the target timestamp,
  stored in `s3://<BACKUP_BUCKET>/wal/`.
- PostgreSQL 16 installed on the recovery host.

### Steps

```bash
# 1. Restore the base snapshot (follow Section 1 steps 1–5 above)
#    Use the most recent snapshot BEFORE your target recovery timestamp.

# 2. Configure recovery in postgresql.conf
cat >> /etc/postgresql/16/main/postgresql.conf <<EOF
restore_command = 'aws s3 cp s3://<BACKUP_BUCKET>/wal/%f %p'
recovery_target_time = '2026-03-27 14:30:00 UTC'
recovery_target_action = 'promote'
EOF

# 3. Create recovery signal file
touch /var/lib/postgresql/16/main/recovery.signal

# 4. Start PostgreSQL — it will replay WAL up to the target time
pg_ctlcluster 16 main start

# 5. Monitor recovery progress
tail -f /var/log/postgresql/postgresql-16-main.log

# 6. Once promoted, verify data (see Section 3)
```

### Expected duration
Approximately **30–90 minutes** depending on the volume of WAL to replay.

---

## 3. Verify a Restored Database Before Promoting to Production

Run these checks against the restored instance before switching any traffic.

```bash
RESTORE_URL="postgresql://postgres:<password>@<TARGET_HOST>/aframp_restore"

# 3a. Key table row counts
for TABLE in transactions wallets payment_provider_configs exchange_rate_history; do
  COUNT=$(psql "$RESTORE_URL" -tAc "SELECT COUNT(*) FROM ${TABLE}")
  echo "${TABLE}: ${COUNT} rows"
done

# 3b. Schema migration count
psql "$RESTORE_URL" -tAc "SELECT COUNT(*) FROM _sqlx_migrations"

# 3c. Most recent transaction timestamp (should be close to recovery point)
psql "$RESTORE_URL" -tAc \
  "SELECT MAX(created_at) FROM transactions"

# 3d. Spot-check a known transaction
psql "$RESTORE_URL" -tAc \
  "SELECT transaction_id, status, created_at FROM transactions ORDER BY created_at DESC LIMIT 5"

# 3e. Confirm no replication slots are blocking WAL retention
psql "$RESTORE_URL" -tAc \
  "SELECT slot_name, active FROM pg_replication_slots"
```

Only promote the restored instance to production once all checks pass and the
team lead has signed off.

---

## 4. Recovery Time Objectives

| Scenario | RTO estimate | RPO estimate |
|---|---|---|
| Restore from daily snapshot | 15–30 min restore + 15 min verification | Up to 24 hours |
| Point-in-time recovery (WAL) | 30–90 min restore + 15 min verification | Up to 5 minutes (WAL lag threshold) |

These estimates assume a 50 GB database and a 1 Gbps network link to the
backup bucket. Adjust for your actual database size.

---

## 5. Restoration Drill Log

A full restoration drill must be completed before Phase 9 sign-off and
repeated at least quarterly thereafter.

| Date | Performed by | Snapshot used | Recovery type | Outcome | Notes |
|---|---|---|---|---|---|
| _(pending)_ | | | | | Drill to be completed before Phase 9 |

### Drill procedure
1. Spin up an isolated PostgreSQL instance (e.g. a separate RDS instance or
   local Docker container — **never** the production instance).
2. Follow Section 1 (snapshot restore) or Section 2 (PITR) as appropriate.
3. Run all verification checks from Section 3.
4. Record the outcome in the table above, including any issues encountered.
5. Tear down the isolated instance.
6. Update this document with lessons learned.
