# B-SEA Phase 3C-4A: Audit Data Model & Append-Only Database Foundation

## 1. Executive Summary

Phase 3C-4A establishes the authoritative, tamper-evident, append-only database foundation for the Bharat Secure Examination Architecture (B-SEA). It implements the approved **Rev-03 decoupled three-table architecture**, resolving the PostgreSQL transaction commit ordering dilemma through **Sealer-Assigned Canonical Incorporation Order** (`audit_chain_links.chain_seq`).

Database-level PostgreSQL triggers strictly prevent any `UPDATE` or `DELETE` across all audit tables, guaranteeing absolute immutability directly in the database engine without relying on application-level enforcement.

---

## 2. Decoupled Three-Table Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                        TABLE 1: audit_logs                             │
│       (Authoritative Raw Security & Application Audit Events)          │
├────────────────────────────────────────────────────────────────────────┤
│ id: VARCHAR(36) [PK, UUIDv4/v7]                                        │
│ event_type: VARCHAR(100) [NOT NULL]                                    │
│ actor_id: VARCHAR(36) [NULLABLE, INDEXED]                              │
│ actor_role: VARCHAR(50) [NULLABLE]                                     │
│ resource_type: VARCHAR(100) [NULLABLE]                                 │
│ resource_id: VARCHAR(36) [NULLABLE, INDEXED]                           │
│ action: VARCHAR(200) [NULLABLE]                                        │
│ result: VARCHAR(20) [NOT NULL] ('SUCCESS', 'FAILURE', 'BLOCKED')       │
│ ip_hash: VARCHAR(64) [NULLABLE]                                        │
│ device_id: VARCHAR(200) [NULLABLE]                                     │
│ event_metadata: JSONB [NULLABLE]                                       │
│ risk_score: FLOAT [DEFAULT 0.0]                                        │
│ event_hash: VARCHAR(128) [NOT NULL] (SHA-256 of Canonical Event JSON)  │
│ trace_id: VARCHAR(64) [NULLABLE, INDEXED]                              │
│ kms_request_id: VARCHAR(64) [NULLABLE]                                 │
│ created_at: TIMESTAMPTZ [NOT NULL, DEFAULT NOW(), INDEXED]             │
│ timestamp: TIMESTAMPTZ [NOT NULL, DEFAULT NOW(), INDEXED] (Legacy)     │
│ seq: INTEGER [NULLABLE] (Legacy compatibility)                         │
│ prev_hash: VARCHAR(128) [NULLABLE] (Legacy compatibility)              │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ 1:1
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     TABLE 2: audit_chain_links                         │
│               (Append-Only Cryptographic Hash Chain)                   │
├────────────────────────────────────────────────────────────────────────┤
│ link_id: BIGSERIAL / BIGINT [PK]                                       │
│ chain_seq: BIGINT [NOT NULL, UNIQUE, INDEXED] (1, 2, 3... Contiguous)  │
│ audit_log_id: VARCHAR(36) [NOT NULL, UNIQUE, FK -> audit_logs.id]      │
│ event_hash: VARCHAR(64) [NOT NULL]                                     │
│ prev_chain_hash: VARCHAR(64) [NOT NULL]                                │
│ chain_hash: VARCHAR(64) [NOT NULL] (SHA256(prev || event_hash || seq)) │
│ created_at: TIMESTAMPTZ [NOT NULL, DEFAULT NOW(), INDEXED]             │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ N:1
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     TABLE 3: audit_epoch_seals                         │
│               (Append-Only KMS Ed25519 Signed Epochs)                  │
├────────────────────────────────────────────────────────────────────────┤
│ epoch_id: BIGINT [PK] (Epoch number: 1, 2, 3...)                       │
│ policy_version: VARCHAR(32) [NOT NULL] ('BSEA-AUDIT-v1')               │
│ start_chain_seq: BIGINT [NOT NULL, INDEXED]                            │
│ end_chain_seq: BIGINT [NOT NULL, UNIQUE]                               │
│ record_count: INTEGER [NOT NULL]                                       │
│ prev_seal_hash: VARCHAR(64) [NOT NULL]                                 │
│ final_chain_hash: VARCHAR(64) [NOT NULL]                               │
│ epoch_root_hash: VARCHAR(64) [NOT NULL]                                │
│ signature_b64: TEXT [NOT NULL] (KMS Ed25519 Signature)                 │
│ kms_key_id: VARCHAR(256) [NOT NULL] (KMS Key ARN)                      │
│ created_at: TIMESTAMPTZ [NOT NULL, DEFAULT NOW(), INDEXED]             │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Immutability Enforcement Mechanism

Immutability is enforced at the PostgreSQL engine level via `BEFORE UPDATE OR DELETE` triggers backed by a single hardened PL/pgSQL trigger function:

```sql
CREATE OR REPLACE FUNCTION trg_prevent_audit_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Table % is strictly immutable. UPDATE and DELETE operations are forbidden.', TG_TABLE_NAME
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_logs_immutable
BEFORE UPDATE OR DELETE ON audit_logs
FOR EACH ROW
EXECUTE FUNCTION trg_prevent_audit_mutation();

CREATE TRIGGER trg_audit_chain_links_immutable
BEFORE UPDATE OR DELETE ON audit_chain_links
FOR EACH ROW
EXECUTE FUNCTION trg_prevent_audit_mutation();

CREATE TRIGGER trg_audit_epoch_seals_immutable
BEFORE UPDATE OR DELETE ON audit_epoch_seals
FOR EACH ROW
EXECUTE FUNCTION trg_prevent_audit_mutation();
```

Any attempted SQL `UPDATE` or `DELETE` statement against any of these three tables immediately raises an `IntegrityConstraintViolationError` (PostgreSQL error code `integrity_constraint_violation`).

---

## 4. Canonical Event Hashing Specification

The canonical representation is implemented in `app.modules.audit.canonical` following RFC 8785 deterministic JSON canonicalization.

### Participating Fields (16 total)
| Index | Field Name | Type | Serialization / Normalization |
|:---|:---|:---|:---|
| 1 | `version` | `int` | Integer schema version (`1`) |
| 2 | `id` | `str` | UUID string |
| 3 | `event_type` | `str` | Exact event identifier |
| 4 | `actor_id` | `str \| None` | User UUID or `null` |
| 5 | `actor_role` | `str \| None` | Role string or `null` |
| 6 | `resource_type`| `str \| None` | Resource classification or `null` |
| 7 | `resource_id` | `str \| None` | Resource UUID or `null` |
| 8 | `action` | `str \| None` | Specific action or `null` |
| 9 | `result` | `str` | Normalized string (`SUCCESS`, `FAILURE`, `BLOCKED`) |
| 10 | `ip_hash` | `str \| None` | SHA-256 IP digest or `null` |
| 11 | `device_id` | `str \| None` | Device identifier or `null` |
| 12 | `event_metadata`| `dict` | Lexicographically sorted nested JSON object |
| 13 | `risk_score` | `float` | Deterministic float representation |
| 14 | `trace_id` | `str \| None` | W3C distributed trace ID or `null` |
| 15 | `kms_request_id`| `str \| None` | AWS KMS operation RequestId or `null` |
| 16 | `created_at` | `str` | ISO 8601 UTC timestamp with `+00:00` offset |

### Excluded Fields
The following fields are assigned asynchronously during sealing and **never** participate in the insertion-time event hash:
- `chain_seq`
- `prev_chain_hash`
- `chain_hash`
- `link_id`
- `epoch_id`

---

## 5. Constraints & Range Invariants

### `audit_chain_links` Constraints
- Primary Key: `link_id` (`BIGINT`, autoincrement)
- `uq_audit_chain_links_chain_seq`: Strict uniqueness of `chain_seq`
- `uq_audit_chain_links_audit_log_id`: Strict 1:1 relation to `audit_logs`
- `fk_audit_chain_links_audit_log_id`: Foreign key referencing `audit_logs(id)` with `ON DELETE RESTRICT`

### `audit_epoch_seals` Range Constraints
- Primary Key: `epoch_id` (`BIGINT`)
- `uq_audit_epoch_seals_end_chain_seq`: Each `end_chain_seq` can only be sealed once
- `ck_audit_epoch_seals_positive_seq`: `CHECK (start_chain_seq >= 1)`
- `ck_audit_epoch_seals_seq_range`: `CHECK (start_chain_seq <= end_chain_seq)`
- `ck_audit_epoch_seals_record_count`: `CHECK (record_count > 0)`
- `ck_audit_epoch_seals_count_match`: `CHECK (record_count = (end_chain_seq - start_chain_seq + 1))`

---

## 6. Migration Safety & Verification

Alembic migration revision `e5f6a7b8c9d0` was tested and verified:
1. **Zero Data Loss:** All 5,614 existing historical records in `audit_logs` were preserved.
2. **Backfill Integrity:** Column `created_at` was populated from `timestamp` for all historical rows (`created_at IS NULL: 0`).
3. **Reversibility:** Fully verified through complete `upgrade -> downgrade -> upgrade` cycle.
4. **Zero Destructive Operations:** Existing `seq` and `prev_hash` columns were safely relaxed to `NULLABLE` for backward compatibility without dropping data.
