# ── Test 10: malformed epoch ranges are rejected ─────────────────────────────

def test_malformed_epoch_ranges_rejected():
    async def _test(conn):
        # Case A: start_chain_seq > end_chain_seq
        with pytest.raises(asyncpg.CheckViolationError) as exc_a:
            async with conn.transaction():
                await conn.execute("""
                    INSERT INTO audit_epoch_seals (
                        epoch_id, policy_version, start_chain_seq, end_chain_seq, record_count,
                        prev_seal_hash, final_chain_hash, epoch_root_hash, signature_b64, kms_key_id, created_at
                    ) VALUES (
                        99101, 'BSEA-AUDIT-v1', 200, 100, 100,
                        'p', 'f', 'r', 's', 'k', NOW()
                    );
                """)
        assert "ck_audit_epoch_seals" in str(exc_a.value)

        # Case B: record_count <= 0
        with pytest.raises(asyncpg.CheckViolationError) as exc_b:
            async with conn.transaction():
                await conn.execute("""
                    INSERT INTO audit_epoch_seals (
                        epoch_id, policy_version, start_chain_seq, end_chain_seq, record_count,
                        prev_seal_hash, final_chain_hash, epoch_root_hash, signature_b64, kms_key_id, created_at
                    ) VALUES (
                        99102, 'BSEA-AUDIT-v1', 1, 10, 0,
                        'p', 'f', 'r', 's', 'k', NOW()
                    );
                """)
        assert "ck_audit_epoch_seals" in str(exc_b.value)

        # Case C: record_count does not match end_chain_seq - start_chain_seq + 1
        with pytest.raises(asyncpg.CheckViolationError) as exc_c:
            async with conn.transaction():
                await conn.execute("""
                    INSERT INTO audit_epoch_seals (
                        epoch_id, policy_version, start_chain_seq, end_chain_seq, record_count,
                        prev_seal_hash, final_chain_hash, epoch_root_hash, signature_b64, kms_key_id, created_at
                    ) VALUES (
                        99103, 'BSEA-AUDIT-v1', 1, 100, 50,
                        'p', 'f', 'r', 's', 'k', NOW()
                    );
                """)
        assert "ck_audit_epoch_seals_count_match" in str(exc_c.value)

        # Case D: start_chain_seq < 1 (0 or negative)
        with pytest.raises(asyncpg.CheckViolationError) as exc_d:
            async with conn.transaction():
                await conn.execute("""
                    INSERT INTO audit_epoch_seals (
                        epoch_id, policy_version, start_chain_seq, end_chain_seq, record_count,
                        prev_seal_hash, final_chain_hash, epoch_root_hash, signature_b64, kms_key_id, created_at
                    ) VALUES (
                        99104, 'BSEA-AUDIT-v1', 0, 9, 10,
                        'p', 'f', 'r', 's', 'k', NOW()
                    );
                """)
        assert "ck_audit_epoch_seals_positive_seq" in str(exc_d.value)

    run_in_rollback(_test)
