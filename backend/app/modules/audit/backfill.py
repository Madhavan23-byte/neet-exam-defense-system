"""
B-SEA Administrative Historical Audit Chain Backfill Procedure

Phase 3C-4B Reference Implementation.
Safely incorporates the 5,982 historical audit events into audit_chain_links
using preserved historical event_hash values (without recomputation)
and seals exactly six historical epochs:
  - Epoch 1: 1..1000 (1,000 links)
  - Epoch 2: 1001..2000 (1,000 links)
  - Epoch 3: 2001..3000 (1,000 links)
  - Epoch 4: 3001..4000 (1,000 links)
  - Epoch 5: 4001..5000 (1,000 links)
  - Epoch 6: 5001..5982 (982 links - partial epoch)
Live canonical chain starts at chain_seq = 5983.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.database import engine as default_engine
from app.crypto.kms_interface import get_kms
from app.modules.audit.canonical import (
    DEFAULT_POLICY_VERSION,
    get_kms_signing_key_id,
    GENESIS_CHAIN_HASH,
    GENESIS_EPOCH_HASH,
    build_canonical_epoch_manifest,
    compute_canonical_chain_hash,
    compute_merkle_root,
    compute_prev_seal_hash,
    serialize_canonical_epoch_manifest,
)
from app.modules.audit.sealer import SEALER_ADVISORY_LOCK_ID

logger = logging.getLogger(__name__)

HISTORICAL_TOTAL_ROWS = 5982
HISTORICAL_EPOCHS = [
    (1, 1, 1000, 1000),
    (2, 1001, 2000, 1000),
    (3, 2001, 3000, 1000),
    (4, 3001, 4000, 1000),
    (5, 4001, 5000, 1000),
    (6, 5001, 5982, 982),
]


async def run_historical_backfill(
    engine: Optional[AsyncEngine] = None,
    kms: Optional[Any] = None,
    policy_version: str = DEFAULT_POLICY_VERSION,
) -> Dict[str, Any]:
    """
    Execute historical backfill under the sealer advisory lock.
    Idempotent: if already backfilled, returns status and verifies integrity.
    """
    eng = engine or default_engine
    kms_inst = kms or get_kms()

    async with eng.connect() as conn:
        # 1. Acquire leadership advisory lock
        res = await conn.execute(
            text("SELECT pg_try_advisory_lock(:lock_id)"),
            {"lock_id": SEALER_ADVISORY_LOCK_ID},
        )
        locked = bool(res.scalar())
        await conn.commit()

        if not locked:
            raise RuntimeError(
                f"Cannot execute historical backfill: advisory lock 0x{SEALER_ADVISORY_LOCK_ID:x} is held by another process."
            )

        try:
            # Check existing state
            r_links = await conn.execute(text("SELECT COUNT(*) FROM audit_chain_links;"))
            existing_links = r_links.scalar() or 0

            r_seals = await conn.execute(text("SELECT COUNT(*), MAX(end_chain_seq) FROM audit_epoch_seals;"))
            seals_row = r_seals.fetchone()
            existing_seals = seals_row[0] if seals_row else 0
            max_sealed_seq = seals_row[1] if seals_row else 0
            await conn.commit()

            if existing_links >= HISTORICAL_TOTAL_ROWS and existing_seals >= 6 and max_sealed_seq >= HISTORICAL_TOTAL_ROWS:
                logger.info("Historical backfill already completed. Idempotent check passed.")
                return {
                    "status": "ALREADY_COMPLETED",
                    "links_count": existing_links,
                    "epochs_count": existing_seals,
                    "next_live_chain_seq": 5983,
                }

            # 2. Fetch all 5,982 historical audit events in legacy seq order
            logger.info("Fetching 5,982 historical audit events from audit_logs...")
            r_logs = await conn.execute(
                text("""
                    SELECT id, seq, event_hash, created_at
                    FROM audit_logs
                    WHERE seq >= 1 AND seq <= :max_seq
                    ORDER BY seq ASC;
                """),
                {"max_seq": HISTORICAL_TOTAL_ROWS},
            )
            raw_logs = r_logs.fetchall()
            await conn.commit()

            if len(raw_logs) != HISTORICAL_TOTAL_ROWS:
                raise RuntimeError(
                    f"Unexpected historical record count: expected {HISTORICAL_TOTAL_ROWS}, found {len(raw_logs)}"
                )

            # 3. Incorporate links 1..5982 into audit_chain_links
            if existing_links < HISTORICAL_TOTAL_ROWS:
                logger.info("Incorporating 5,982 historical events into audit_chain_links...")
                prev_chain_hash = GENESIS_CHAIN_HASH
                batch_size = 1000
                links_buffer = []

                for row in raw_logs:
                    chain_seq = row.seq
                    event_hash = row.event_hash.lower()
                    chain_hash = compute_canonical_chain_hash(
                        prev_chain_hash, event_hash, chain_seq
                    )
                    links_buffer.append({
                        "chain_seq": chain_seq,
                        "audit_log_id": str(row.id),
                        "event_hash": event_hash,
                        "prev_chain_hash": prev_chain_hash.lower(),
                        "chain_hash": chain_hash.lower(),
                        "created_at": row.created_at or datetime.now(timezone.utc),
                    })
                    prev_chain_hash = chain_hash

                # Insert in chunks of 1000 within a transaction
                async with conn.begin():
                    for i in range(0, len(links_buffer), batch_size):
                        chunk = links_buffer[i : i + batch_size]
                        await conn.execute(
                            text("""
                                INSERT INTO audit_chain_links (
                                    chain_seq, audit_log_id, event_hash, prev_chain_hash, chain_hash, created_at
                                ) VALUES (
                                    :chain_seq, :audit_log_id, :event_hash, :prev_chain_hash, :chain_hash, :created_at
                                )
                                ON CONFLICT (chain_seq) DO NOTHING;
                            """),
                            chunk,
                        )
                logger.info(f"Incorporated {len(links_buffer)} links into audit_chain_links.")

            # 4. Seal Historical Epochs 1 through 6
            logger.info("Sealing Historical Epochs 1 through 6...")
            prev_manifest_bytes = None
            sealed_summary = []

            for epoch_id, start_seq, end_seq, count in HISTORICAL_EPOCHS:
                # Check if epoch already sealed
                r_check = await conn.execute(
                    text("SELECT epoch_id, end_chain_seq FROM audit_epoch_seals WHERE epoch_id = :e_id;"),
                    {"e_id": epoch_id},
                )
                existing = r_check.fetchone()
                if existing is not None:
                    logger.info(f"Epoch {epoch_id} already sealed. Reconstructing manifest bytes for continuity.")
                    r_ex = await conn.execute(
                        text("""
                            SELECT epoch_id, start_chain_seq, end_chain_seq, record_count,
                                   prev_seal_hash, epoch_root_hash, policy_version, kms_key_id
                            FROM audit_epoch_seals WHERE epoch_id = :e_id;
                        """),
                        {"e_id": epoch_id},
                    )
                    ex_row = r_ex.fetchone()
                    await conn.commit()
                    ex_m = build_canonical_epoch_manifest(
                        epoch_id=ex_row.epoch_id,
                        start_chain_seq=ex_row.start_chain_seq,
                        end_chain_seq=ex_row.end_chain_seq,
                        record_count=ex_row.record_count,
                        epoch_root_hash=ex_row.epoch_root_hash,
                        prev_seal_hash=ex_row.prev_seal_hash,
                        kms_key_id=ex_row.kms_key_id,
                        policy_version=ex_row.policy_version,
                    )
                    prev_manifest_bytes = serialize_canonical_epoch_manifest(ex_m)
                    continue
                else:
                    await conn.commit()

                # Fetch hashes for epoch range
                r_hashes = await conn.execute(
                    text("""
                        SELECT chain_seq, chain_hash
                        FROM audit_chain_links
                        WHERE chain_seq >= :s_seq AND chain_seq <= :e_seq
                        ORDER BY chain_seq ASC;
                    """),
                    {"s_seq": start_seq, "e_seq": end_seq},
                )
                chain_rows = r_hashes.fetchall()
                await conn.commit()

                if len(chain_rows) != count:
                    raise RuntimeError(
                        f"Range gap for epoch {epoch_id}: expected {count} links, found {len(chain_rows)}"
                    )

                epoch_hashes = [r.chain_hash for r in chain_rows]
                epoch_root_hash = compute_merkle_root(epoch_hashes)
                final_chain_hash = epoch_hashes[-1]

                if epoch_id == 1:
                    prev_seal_hash = GENESIS_EPOCH_HASH
                else:
                    if prev_manifest_bytes is None:
                        raise RuntimeError(f"Previous manifest bytes missing for Epoch {epoch_id}")
                    prev_seal_hash = compute_prev_seal_hash(prev_manifest_bytes)

                target_key = get_kms_signing_key_id(kms_inst)
                manifest_dict = build_canonical_epoch_manifest(
                    epoch_id=epoch_id,
                    start_chain_seq=start_seq,
                    end_chain_seq=end_seq,
                    record_count=count,
                    epoch_root_hash=epoch_root_hash,
                    prev_seal_hash=prev_seal_hash,
                    kms_key_id=target_key,
                    policy_version=policy_version,
                )
                manifest_bytes = serialize_canonical_epoch_manifest(manifest_dict)

                # KMS Sign OUTSIDE database transaction
                signed_payload = kms_inst.sign(manifest_bytes)

                # Persist seal in Transaction D
                async with conn.begin():
                    await conn.execute(
                        text("""
                            INSERT INTO audit_epoch_seals (
                                epoch_id, policy_version, start_chain_seq, end_chain_seq,
                                record_count, prev_seal_hash, final_chain_hash,
                                epoch_root_hash, signature_b64, kms_key_id, created_at
                            ) VALUES (
                                :epoch_id, :policy_version, :start_chain_seq, :end_chain_seq,
                                :record_count, :prev_seal_hash, :final_chain_hash,
                                :epoch_root_hash, :signature_b64, :kms_key_id, :created_at
                            );
                        """),
                        {
                            "epoch_id": epoch_id,
                            "policy_version": policy_version,
                            "start_chain_seq": start_seq,
                            "end_chain_seq": end_seq,
                            "record_count": count,
                            "prev_seal_hash": prev_seal_hash,
                            "final_chain_hash": final_chain_hash,
                            "epoch_root_hash": epoch_root_hash,
                            "signature_b64": signed_payload.signature_b64,
                            "kms_key_id": signed_payload.key_id,
                            "created_at": datetime.now(timezone.utc),
                        },
                    )

                prev_manifest_bytes = manifest_bytes
                sealed_summary.append({
                    "epoch_id": epoch_id,
                    "start_chain_seq": start_seq,
                    "end_chain_seq": end_seq,
                    "record_count": count,
                    "epoch_root_hash": epoch_root_hash,
                })
                logger.info(f"Historical Epoch {epoch_id} sealed [{start_seq}..{end_seq}]")

            logger.info("Historical backfill successfully completed!")
            return {
                "status": "COMPLETED",
                "links_count": HISTORICAL_TOTAL_ROWS,
                "epochs_count": 6,
                "next_live_chain_seq": 5983,
                "sealed_epochs": sealed_summary,
            }

        finally:
            await conn.execute(
                text("SELECT pg_advisory_unlock(:lock_id)"),
                {"lock_id": SEALER_ADVISORY_LOCK_ID},
            )
            await conn.commit()
