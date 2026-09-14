# B-SEA Phase 3C-4A: Audit Data Model & Append-Only Database Foundation

## 1. Purpose
The purpose of Phase 3C-4A is to establish the append-only, tamper-evident database foundation for audit logging within the Bharat Secure Examination Architecture (B-SEA). This phase introduces the data structures, database constraints, PostgreSQL triggers, and deterministic canonical hashing required for audit integrity, while strictly separating raw event storage from later cryptographic sealing.

---

## 2. Relationship to Approved Rev-03 Architecture
Phase 3C-4 Rev-03 resolved the fundamental limitation of assuming database transaction commit order is chronological or queryable by insertion timestamps.
Under Rev-03:
- Database transaction commit order is **NOT** authoritative and is **NOT** claimed to be recoverable from `created_at`.
- Canonical audit sequence is defined strictly by **Sealer-Assigned Canonical Incorporation Order** (`audit_chain_links.chain_seq`).
- The database architecture is decoupled into three distinct append-only tables:
  1. `audit_logs`: Raw application and security audit events.
  2. `audit_chain_links`: Cryptographic hash chain links assigned by the background sealer.
  3. `audit_epoch_seals`: Periodic cryptographic epoch checkpoints.

Phase 3C-4A implements the database schema, constraints, and immutability triggers for this three-table architecture.

---

## 3. `audit_logs` Schema (Raw Application & Security Events)
Stores raw, immutable audit events at row creation time. No canonical sequence number is assigned at this layer.

| Column | Type | Constraints | Description |
|:---|:---|:---|:---|
| `id` | `VARCHAR(36)` | `PRIMARY KEY` | Unique event UUID (UUIDv4/UUIDv7 string) |
| `event_type` | `VARCHAR(100)` | `NOT NULL`, `INDEX` | Categorical event identifier |
| `actor_id` | `VARCHAR(36)` | `NULLABLE`, `INDEX` | User or system actor UUID |
| `actor_role` | `VARCHAR(50)` | `NULLABLE` | Role of actor at execution time |
| `resource_type` | `VARCHAR(100)` | `NULLABLE` | Target entity type (`exam`, `question`, etc.) |
| `resource_id` | `VARCHAR(36)` | `NULLABLE`, `INDEX` | Target entity UUID |
| `action` | `VARCHAR(200)` | `NULLABLE` | Specific operational verb or description |
| `result` | `VARCHAR(20)` | `NOT NULL` | Outcome (`SUCCESS`, `FAILURE`, `BLOCKED`) |
| `ip_hash` | `VARCHAR(64)` | `NULLABLE` | SHA-256 pseudonymized IP address |
| `device_id` | `VARCHAR(200)` | `NULLABLE` | Device / workstation identifier |
| `event_metadata` | `JSONB` | `NULLABLE` | Structured event context |
| `risk_score` | `FLOAT` | `NOT NULL`, `DEFAULT 0.0` | Heuristic risk score |
| `event_hash` | `VARCHAR(128)` | `NOT NULL` | SHA-256 digest of canonical event JSON |
| `trace_id` | `VARCHAR(64)` | `NULLABLE`, `INDEX` | W3C distributed trace context ID |
| `kms_request_id` | `VARCHAR(64)` | `NULLABLE` | Correlated AWS KMS RequestId |
| `created_at` | `TIMESTAMPTZ` | `NOT NULL`, `DEFAULT NOW()`, `INDEX` | Authoritative row insertion timestamp |
| `timestamp` | `TIMESTAMPTZ` | `NOT NULL`, `DEFAULT NOW()`, `INDEX` | Preserved for legacy endpoint compatibility |
| `seq` | `INTEGER` | `NULLABLE` | Preserved for legacy compatibility (sealer uses `chain_seq`) |
| `prev_hash` | `VARCHAR(128)` | `NULLABLE` | Preserved for legacy compatibility (sealer uses `prev_chain_hash`) |

---

## 4. `audit_chain_links` Schema (Append-Only Hash Chain)
Maintains the linear cryptographic hash chain. Each record links exactly one raw audit log into the canonical sequence.

| Column | Type | Constraints | Description |
|:---|:---|:---|:---|
| `link_id` | `BIGINT` | `PRIMARY KEY`, `AUTOINCREMENT` | Physical table sequence |
| `chain_seq` | `BIGINT` | `NOT NULL`, `UNIQUE`, `INDEX` | Monotonic, contiguous canonical sequence ($1, 2, 3...$) |
| `audit_log_id` | `VARCHAR(36)` | `NOT NULL`, `UNIQUE`, `INDEX`, `FK` | 1:1 Reference to `audit_logs.id` |
| `event_hash` | `VARCHAR(64)` | `NOT NULL` | Mirror of `audit_logs.event_hash` |
| `prev_chain_hash`| `VARCHAR(64)` | `NOT NULL` | Preceding link `chain_hash` or Genesis |
| `chain_hash` | `VARCHAR(64)` | `NOT NULL` | $\text{SHA256}(\text{prev} \parallel \text{event\_hash} \parallel \text{seq})$ |
| `created_at` | `TIMESTAMPTZ` | `NOT NULL`, `DEFAULT NOW()`, `INDEX` | Timestamp when link was sealed |

---

## 5. `audit_epoch_seals` Schema (Immutable Epoch Checkpoints)
Maintains signed epoch commitments over ranges of chain links.

| Column | Type | Constraints | Description |
|:---|:---|:---|:---|
| `epoch_id` | `BIGINT` | `PRIMARY KEY` | Monotonic epoch sequence ($1, 2, 3...$) |
| `policy_version`| `VARCHAR(32)` | `NOT NULL` | Active sealing policy (`BSEA-AUDIT-v1`) |
| `start_chain_seq`| `BIGINT` | `NOT NULL`, `INDEX` | First `chain_seq` included in this epoch |
| `end_chain_seq` | `BIGINT` | `NOT NULL`, `UNIQUE` | Last `chain_seq` included in this epoch |
| `record_count` | `INTEGER` | `NOT NULL` | Total count of links in epoch |
| `prev_seal_hash`| `VARCHAR(64)` | `NOT NULL` | SHA-256 of preceding epoch seal payload |
| `final_chain_hash`|`VARCHAR(64)` | `NOT NULL` | `chain_hash` of link at `end_chain_seq` |
| `epoch_root_hash`| `VARCHAR(64)` | `NOT NULL` | SHA-256 Merkle / root hash of epoch links |
| `signature_b64` | `TEXT` | `NOT NULL` | Base64-encoded Ed25519 digital signature |
| `kms_key_id` | `VARCHAR(256)`| `NOT NULL` | KMS Key ARN used to sign epoch |
| `created_at` | `TIMESTAMPTZ` | `NOT NULL`, `DEFAULT NOW()`, `INDEX` | Epoch seal creation timestamp |

---

## 6. Canonical Event Hash Definition
Implemented in `backend/app/modules/audit/canonical.py`.

The hash is computed using deterministic key-sorted compact JSON serialization following RFC 8785 principles using Python's standard json implementation:
$$\text{event\_hash} = \text{SHA256}(\text{CanonicalJSON}(\text{payload}))$$

### Included Fields (16 total):
1. `version`: integer (`1`)
2. `id`: string (UUID)
3. `event_type`: string
4. `actor_id`: string or `null`
5. `actor_role`: string or `null`
6. `resource_type`: string or `null`
7. `resource_id`: string or `null`
8. `action`: string or `null`
9. `result`: string (`SUCCESS`, `FAILURE`, `BLOCKED`)
10. `ip_hash`: string or `null`
11. `device_id`: string or `null`
12. `event_metadata`: dictionary (keys lexicographically sorted recursively)
13. `risk_score`: float
14. `trace_id`: string or `null`
15. `kms_request_id`: string or `null`
16. `created_at`: string (ISO 8601 UTC representation with explicit offset `+00:00`)

### Excluded Fields:
Mutable and sealer-assigned fields (`chain_seq`, `prev_chain_hash`, `chain_hash`, `link_id`, `epoch_id`) are strictly excluded because events must be hashed at insertion time before sealing occurs.

---

## 7. Immutability Enforcement Mechanism
Audit mutations are rejected at the PostgreSQL database layer and cannot be performed through normal application/ORM operations. Administrative database privileges remain a separate trust boundary.

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
FOR EACH ROW EXECUTE FUNCTION trg_prevent_audit_mutation();

CREATE TRIGGER trg_audit_chain_links_immutable
BEFORE UPDATE OR DELETE ON audit_chain_links
FOR EACH ROW EXECUTE FUNCTION trg_prevent_audit_mutation();

CREATE TRIGGER trg_audit_epoch_seals_immutable
BEFORE UPDATE OR DELETE ON audit_epoch_seals
FOR EACH ROW EXECUTE FUNCTION trg_prevent_audit_mutation();
```

---

## 8. Foreign Key Behavior
The relationship between `audit_chain_links` and `audit_logs` is protected by a strict foreign key:
```sql
CONSTRAINT fk_audit_chain_links_audit_log_id
FOREIGN KEY (audit_log_id) REFERENCES audit_logs (id)
ON DELETE RESTRICT;
```
`CASCADE DELETE` is forbidden. Even if the immutability trigger were bypassed, foreign key restrictions prevent orphan creation or deletion of referenced audit events.

---

## 9. Constraints and Invariants
1. **Contiguity & Uniqueness:**
   - `uq_audit_chain_links_chain_seq`: guarantees single ownership of each sequence position.
   - `uq_audit_chain_links_audit_log_id`: guarantees exactly-once incorporation.
2. **Epoch Range Integrity:**
   - `uq_audit_epoch_seals_end_chain_seq`: prevents duplicate seals on the same boundary.
   - `ck_audit_epoch_seals_positive_seq`: `CHECK (start_chain_seq >= 1)`
   - `ck_audit_epoch_seals_seq_range`: `CHECK (start_chain_seq <= end_chain_seq)`
   - `ck_audit_epoch_seals_record_count`: `CHECK (record_count > 0)`
   - `ck_audit_epoch_seals_count_match`: `CHECK (record_count = (end_chain_seq - start_chain_seq + 1))`

---

## 10. Migration Strategy
Alembic migration `e5f6a7b8c9d0_phase3c4_decoupled_audit.py`:
- **Non-Destructive:** Existing rows in `audit_logs` are preserved.
- **Safe Backfill:** `created_at` is populated from `timestamp` for all historical rows prior to enforcing `NOT NULL`.
- **Backward Compatibility:** `seq` and `prev_hash` are relaxed to `NULLABLE` so historical rows remain intact while new rows do not depend on pseudo-sequences.
- **Reversible:** Downgrade safely drops triggers, constraints, tables, and restored column definitions without leaving orphans.

---

## 11. Tests Performed
Test file: `backend/tests/security/test_phase3c4a_database_immutability.py` (18 tests total):
- Test 1: `UPDATE audit_logs` is rejected by trigger.
- Test 2: `DELETE audit_logs` is rejected by trigger.
- Test 3: `UPDATE audit_chain_links` is rejected by trigger.
- Test 4: `DELETE audit_chain_links` is rejected by trigger.
- Test 5: `UPDATE audit_epoch_seals` is rejected by trigger.
- Test 6: `DELETE audit_epoch_seals` is rejected by trigger.
- Test 7: Duplicate `chain_seq` rejected by unique constraint.
- Test 8: Duplicate `audit_log_id` rejected by unique constraint.
- Test 9: Invalid `audit_log_id` FK rejected by foreign key constraint.
- Test 10: Malformed epoch range rejected by check constraints.
- Test 11: Existing audit rows remain intact after migration.
- Test 12: Triggers exist in PostgreSQL catalog after migration.
- Test 13: Triggers are removed during Alembic downgrade.
- Test 14: Upgrade $\rightarrow$ Downgrade $\rightarrow$ Upgrade cycle succeeds.
- Test 15: Canonical event hash is deterministic across executions.
- Test 16: Key order independence verified (canonical key-sorted JSON).
- Test 17: Mutating any of the 16 participating fields produces distinct hashes.
- Test 18: Chain-link constraints reject NULL or non-existent references.

**Result:** 18/18 PASSED.

---

## 12. Regression Results
All existing security suites passed:
- Phase 3C-3 KMS: 26/26 passed
- Phase 0 Fixes: 12/12 passed
- Phase 2 Sharding: 14/14 passed
- Phase 3A Ephemeral Auth: 20/20 passed
- Phase 3B Break-Glass: 30/30 passed
- Phase 3C-1 Cloud Foundation: 13/13 passed
- Attacks Suite: 16 passed, 5 skipped (expected baseline)
- Concurrency & Race Suites: 6/6 passed
- Frontend Production Build: Passed (1.22s)
- Terraform Validate: Valid

---

## 13. Prototype & Scope Limitations
1. Audit logs written prior to Phase 3C-4B remain unlinked in `audit_chain_links` until the sealer is deployed.
2. Direct database updates or deletions require explicit trigger drops or transaction rollbacks during automated test isolation.

---

## 14. Explicit Statement: Canonical Ordering Is NOT Implemented Yet
**Canonical ordering is NOT implemented in Phase 3C-4A.**
Sequence numbers are not automatically assigned, background linking is not running, and advisory-lock leader election has not been deployed. Sequence allocation belongs exclusively to the Phase 3C-4B sealer.

---

## 15. Explicit Statement: KMS Signing Is NOT Implemented Yet
**AWS KMS Ed25519 epoch signing is NOT implemented in Phase 3C-4A.**
No external KMS network calls, epoch aggregation services, or signature generations are performed in this phase. Epoch sealing belongs exclusively to Phase 3C-4B.
