import sys
import os

# Ensure app is in pythonpath
sys.path.insert(0, r"C:\Users\madha\.gemini\antigravity-ide\scratch\b-sea\backend")

from app.core.database import Base
import app.core.models # ensure all models registered

print("=== TOTAL TABLES IN BASE.METADATA ===")
print(f"Table count: {len(Base.metadata.tables)}")
print("Table names:", list(Base.metadata.tables.keys()))

print("\n=== SORTED TABLES (DEPENDENCY ORDER) ===")
for t in Base.metadata.sorted_tables:
    print(f"- {t.name}")

print("\n=== DETAILED TABLE DEFINITIONS ===")
for t in Base.metadata.sorted_tables:
    print(f"\nTABLE: {t.name}")
    print("  COLUMNS:")
    for c in t.columns:
        fks = [f"{fk.column.table.name}.{fk.column.name}" for fk in c.foreign_keys]
        fk_str = f" -> FK({', '.join(fks)})" if fks else ""
        print(f"    {c.name}: {c.type} | nullable={c.nullable} | pk={c.primary_key}{fk_str}")
    print("  CONSTRAINTS:")
    for cons in t.constraints:
        print(f"    {cons.__class__.__name__}: {cons.name} ({[col.name for col in getattr(cons, 'columns', [])]})")
    print("  INDEXES:")
    for idx in t.indexes:
        where = idx.dialect_options.get('postgresql', {}).get('where')
        where_str = f" WHERE {where}" if where is not None else ""
        print(f"    Index: {idx.name} ({[c.name for c in idx.columns]}) unique={idx.unique}{where_str}")
