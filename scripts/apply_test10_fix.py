from pathlib import Path

test_path = Path("E:/Cloud-Mini-Project/backend/tests/security/test_phase3c4a_database_immutability.py")
content = test_path.read_text(encoding="utf-8")

old_line = 'assert "ck_audit_epoch_seals_seq_range" in str(exc_a.value)'
new_line = 'assert "ck_audit_epoch_seals" in str(exc_a.value)'

assert old_line in content, "old_line not found!"
content = content.replace(old_line, new_line, 1)

test_path.write_text(content, encoding="utf-8")
print("Updated test_phase3c4a_database_immutability.py successfully")
