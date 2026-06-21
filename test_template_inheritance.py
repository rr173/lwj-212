#!/usr/bin/env python3
"""
Test script for template inheritance and diff merge module.
Tests:
1. Template creation with parent template
2. Inheritance constraints (one level only, max 5 children)
3. Full fields merging
4. Parse with merged fields
5. Template diff comparison
6. Batch migration
7. Delete protection for parent templates
"""

import asyncio
import json
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ["DB_PATH"] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "test_protocol_workbench.db")

from app.database import init_db
from app.models import FieldDef


async def test_database():
    """Test database initialization with new columns and tables"""
    print("=" * 60)
    print("TEST 1: Database initialization")
    print("=" * 60)

    if os.path.exists(os.environ["DB_PATH"]):
        os.remove(os.environ["DB_PATH"])

    await init_db()
    print("✓ Database initialized successfully")

    from app.database import get_db
    db = await get_db()
    try:
        rows = await db.execute_fetchall("PRAGMA table_info(templates)")
        col_names = [r["name"] for r in rows]
        print(f"✓ templates columns: {col_names}")
        assert "parent_template_id" in col_names, "parent_template_id column missing in templates"

        rows = await db.execute_fetchall("PRAGMA table_info(template_versions)")
        col_names = [r["name"] for r in rows]
        print(f"✓ template_versions columns: {col_names}")
        assert "parent_template_id" in col_names, "parent_template_id column missing in template_versions"

        for table_name in ["parse_cache", "migration_tasks"]:
            rows = await db.execute_fetchall(
                f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table_name}'"
            )
            assert rows, f"{table_name} table missing"
            print(f"✓ {table_name} table exists")
    finally:
        await db.close()

    print("✓ All database tests passed\n")


async def test_template_inheritance():
    """Test template creation with inheritance"""
    print("=" * 60)
    print("TEST 2: Template inheritance creation")
    print("=" * 60)

    from app.routers.templates import create_template, get_template, get_full_fields, delete_template
    from app.models import TemplateCreate

    parent_fields = [
        FieldDef(name="magic", length_rule="fixed", length_value=2, data_type="uint16_be"),
        FieldDef(name="version", length_rule="fixed", length_value=1, data_type="uint8"),
        FieldDef(name="msg_type", length_rule="fixed", length_value=1, data_type="uint8"),
        FieldDef(name="payload_len", length_rule="fixed", length_value=2, data_type="uint16_be"),
        FieldDef(name="payload", length_rule="ref", length_ref_field="payload_len", data_type="bytes"),
        FieldDef(name="crc16", length_rule="fixed", length_value=2, data_type="uint16_be"),
    ]

    parent = await create_template(TemplateCreate(
        name="Parent Protocol",
        description="Base protocol template",
        fields=parent_fields,
        parent_template_id=None
    ))
    print(f"✓ Created parent template: id={parent.id}, name={parent.name}")
    assert parent.parent_template_id is None
    assert parent.child_template_count == 0

    child_fields = [
        FieldDef(name="msg_type", length_rule="fixed", length_value=1, data_type="uint8", condition_field="version", condition_value="2"),
        FieldDef(name="extra_field", length_rule="fixed", length_value=4, data_type="uint32_be"),
    ]

    child = await create_template(TemplateCreate(
        name="Child Protocol v2",
        description="Extended protocol with extra fields",
        fields=child_fields,
        parent_template_id=parent.id
    ))
    print(f"✓ Created child template: id={child.id}, name={child.name}, parent={child.parent_template_id}")
    assert child.parent_template_id == parent.id

    parent_after = await get_template(parent.id)
    print(f"✓ Parent now has {parent_after.child_template_count} child templates")
    assert parent_after.child_template_count == 1

    full_fields = await get_full_fields(child.id, version=None)
    print(f"✓ Full fields result: total={full_fields.total_fields}, "
          f"inherited={full_fields.inherited_fields}, "
          f"overridden={full_fields.overridden_fields}, "
          f"new={full_fields.new_fields}")

    assert full_fields.total_fields == 7
    assert full_fields.inherited_fields == 5
    assert full_fields.overridden_fields == 1
    assert full_fields.new_fields == 1

    field_names = [f.name for f in full_fields.fields]
    print(f"✓ Merged field order: {field_names}")
    expected_order = ["magic", "version", "msg_type", "payload_len", "payload", "crc16", "extra_field"]
    assert field_names == expected_order, f"Expected {expected_order}, got {field_names}"

    assert full_fields.fields[2].condition_field == "version"
    assert full_fields.fields[2].condition_value == "2"
    print("✓ Overridden field has child's condition attributes")

    print("✓ All template inheritance tests passed\n")
    return parent.id, child.id


async def test_inheritance_constraints(parent_id: int):
    """Test inheritance constraints"""
    print("=" * 60)
    print("TEST 3: Inheritance constraints")
    print("=" * 60)

    from app.routers.templates import create_template
    from app.models import TemplateCreate
    from fastapi import HTTPException

    try:
        await create_template(TemplateCreate(
            name="Grandchild Template",
            description="Should fail - multi-level inheritance",
            fields=[FieldDef(name="test", length_rule="fixed", length_value=1, data_type="uint8")],
            parent_template_id=parent_id + 100
        ))
        print("✗ Should have failed for non-existent parent")
        assert False
    except HTTPException as e:
        print(f"✓ Correctly rejected non-existent parent: {e.detail}")

    child_of_child_fields = [
        FieldDef(name="test", length_rule="fixed", length_value=1, data_type="uint8")
    ]
    try:
        await create_template(TemplateCreate(
            name="Grandchild Template",
            description="Should fail - multi-level inheritance",
            fields=child_of_child_fields,
            parent_template_id=parent_id + 1
        ))
        print("✗ Should have failed for multi-level inheritance")
        assert False
    except HTTPException as e:
        print(f"✓ Correctly rejected multi-level inheritance: {e.detail}")

    for i in range(4):
        await create_template(TemplateCreate(
            name=f"Child Template {i+2}",
            description=f"Test child {i+2}",
            fields=[FieldDef(name=f"field{i}", length_rule="fixed", length_value=1, data_type="uint8")],
            parent_template_id=parent_id
        ))
    print("✓ Created 4 additional child templates (total 5, max allowed)")

    try:
        await create_template(TemplateCreate(
            name="Child Template 7",
            description="Should fail - max children exceeded",
            fields=[FieldDef(name="test", length_rule="fixed", length_value=1, data_type="uint8")],
            parent_template_id=parent_id
        ))
        print("✗ Should have failed for max children exceeded")
        assert False
    except HTTPException as e:
        print(f"✓ Correctly rejected max children exceeded: {e.detail}")

    print("✓ All inheritance constraint tests passed\n")


async def test_delete_protection(parent_id: int, child_id: int):
    """Test delete protection for parent templates"""
    print("=" * 60)
    print("TEST 4: Delete protection")
    print("=" * 60)

    from app.routers.templates import delete_template, list_templates
    from fastapi import HTTPException

    try:
        await delete_template(parent_id)
        print("✗ Should have failed to delete parent with children")
        assert False
    except HTTPException as e:
        print(f"✓ Correctly rejected parent deletion: {e.detail}")

    all_templates = await list_templates(limit=100, offset=0)
    child_templates = [t for t in all_templates if t.parent_template_id == parent_id]
    print(f"✓ Found {len(child_templates)} child templates to delete")

    for child in child_templates:
        await delete_template(child.id)
        print(f"  - Deleted child template {child.id}: {child.name}")

    await delete_template(parent_id)
    print(f"✓ Successfully deleted parent template {parent_id} (after deleting all children)")

    print("✓ All delete protection tests passed\n")


async def test_template_diff():
    """Test template diff comparison"""
    print("=" * 60)
    print("TEST 5: Template diff comparison")
    print("=" * 60)

    from app.routers.templates import create_template, diff_templates
    from app.models import TemplateCreate

    fields_a = [
        FieldDef(name="magic", length_rule="fixed", length_value=2, data_type="uint16_be"),
        FieldDef(name="version", length_rule="fixed", length_value=1, data_type="uint8"),
        FieldDef(name="msg_type", length_rule="fixed", length_value=1, data_type="uint8"),
        FieldDef(name="payload", length_rule="fixed", length_value=10, data_type="bytes"),
        FieldDef(name="crc16", length_rule="fixed", length_value=2, data_type="uint16_be"),
    ]

    fields_b = [
        FieldDef(name="magic", length_rule="fixed", length_value=2, data_type="uint16_be"),
        FieldDef(name="version", length_rule="fixed", length_value=2, data_type="uint16_be"),
        FieldDef(name="msg_type", length_rule="fixed", length_value=1, data_type="uint8", condition_field="version", condition_value="1"),
        FieldDef(name="length", length_rule="fixed", length_value=2, data_type="uint16_be"),
        FieldDef(name="payload", length_rule="ref", length_ref_field="length", data_type="bytes"),
        FieldDef(name="checksum", length_rule="fixed", length_value=1, data_type="uint8"),
    ]

    template_a = await create_template(TemplateCreate(
        name="Template A",
        description="First template",
        fields=fields_a,
    ))

    template_b = await create_template(TemplateCreate(
        name="Template B",
        description="Second template",
        fields=fields_b,
    ))

    diff = await diff_templates(template_a.id, template_b.id, version_a=None, version_b=None)
    print(f"✓ Diff result: same={diff.same_fields}, "
          f"only_a={len(diff.only_a)}, only_b={len(diff.only_b)}, "
          f"modified={len(diff.modified)}")

    assert diff.same_fields == 1
    assert len(diff.only_a) == 1
    assert len(diff.only_b) == 2
    assert len(diff.modified) == 3

    only_a_names = [f.name for f in diff.only_a]
    only_b_names = [f.name for f in diff.only_b]
    modified_names = [f.field_name for f in diff.modified]

    print(f"  - Only in A: {only_a_names}")
    print(f"  - Only in B: {only_b_names}")
    print(f"  - Modified: {modified_names}")

    assert "crc16" in only_a_names
    assert "length" in only_b_names
    assert "checksum" in only_b_names
    assert "magic" in modified_names or "msg_type" in modified_names or "payload" in modified_names

    for m in diff.modified:
        print(f"  - {m.field_name} modifications: {[(a.attribute, a.a_value, a.b_value) for a in m.modified_attributes]}")
        assert len(m.modified_attributes) >= 1

    print("✓ All template diff tests passed\n")
    return template_a.id, template_b.id


async def test_parse_with_inheritance():
    """Test parsing with inherited templates"""
    print("=" * 60)
    print("TEST 6: Parse with inheritance")
    print("=" * 60)

    from app.routers.templates import create_template
    from app.routers.samples import create_sample
    from app.routers.parse import parse_single
    from app.models import TemplateCreate, SampleCreate

    parent_fields = [
        FieldDef(name="magic", length_rule="fixed", length_value=2, data_type="uint16_be"),
        FieldDef(name="length", length_rule="fixed", length_value=2, data_type="uint16_be"),
        FieldDef(name="payload", length_rule="ref", length_ref_field="length", data_type="bytes"),
        FieldDef(name="crc", length_rule="fixed", length_value=1, data_type="uint8"),
    ]

    parent = await create_template(TemplateCreate(
        name="Parse Test Parent",
        description="Parent for parse test",
        fields=parent_fields,
    ))

    child_fields = [
        FieldDef(name="extra", length_rule="fixed", length_value=4, data_type="uint32_be"),
    ]

    child = await create_template(TemplateCreate(
        name="Parse Test Child",
        description="Child for parse test",
        fields=child_fields,
        parent_template_id=parent.id,
    ))

    hex_data = "feed000411223344ff00000001"
    sample = await create_sample(SampleCreate(
        name="Test Sample",
        hex_data=hex_data,
        note="Test sample for inheritance parsing"
    ))

    result_parent = await parse_single(parent.id, sample.id, version=None, use_cache=False)
    print(f"✓ Parent parse: {len(result_parent.fields)} fields, coverage={result_parent.coverage_percent}%")

    result_child = await parse_single(child.id, sample.id, version=None, use_cache=False)
    print(f"✓ Child parse: {len(result_child.fields)} fields, coverage={result_child.coverage_percent}%")

    assert len(result_parent.fields) == 4
    assert len(result_child.fields) == 5

    child_field_names = [f.name for f in result_child.fields]
    print(f"✓ Child parsed fields: {child_field_names}")
    assert "magic" in child_field_names
    assert "length" in child_field_names
    assert "payload" in child_field_names
    assert "crc" in child_field_names
    assert "extra" in child_field_names

    extra_field = next(f for f in result_child.fields if f.name == "extra")
    print(f"✓ Extra field value: {extra_field.value}")
    assert extra_field.value == "1"

    print("✓ All parse with inheritance tests passed\n")
    return parent.id, child.id, sample.id


async def test_batch_migration(source_id: int, target_id: int, sample_id: int):
    """Test batch migration"""
    print("=" * 60)
    print("TEST 7: Batch migration")
    print("=" * 60)

    from app.routers.parse import parse_single
    from app.routers.templates import prepare_migration, execute_migration, get_migration_status
    from app.models import MigrationPrepareRequest, MigrationExecuteRequest

    await parse_single(source_id, sample_id, version=None, use_cache=False)
    print("✓ Pre-populated parse cache with source template")

    prep = await prepare_migration(MigrationPrepareRequest(
        source_template_id=source_id,
        target_template_id=target_id
    ))
    print(f"✓ Migration prepared: task_id={prep.migration_task_id}, "
          f"marked={prep.total_samples_marked} samples")

    status = await get_migration_status(prep.migration_task_id)
    print(f"✓ Migration status: {status.status}, total={status.total_samples}")
    assert status.status == "pending"

    exec_result = await execute_migration(MigrationExecuteRequest(
        migration_task_id=prep.migration_task_id
    ))
    print(f"✓ Migration executed: success={exec_result.success_count}, "
          f"failed={exec_result.failed_count}, skipped={exec_result.skipped_count}")
    assert exec_result.completed

    status = await get_migration_status(prep.migration_task_id)
    print(f"✓ Final status: {status.status}, success={status.success_count}")
    assert status.status == "completed"
    assert status.success_count >= 0

    print("✓ All batch migration tests passed\n")


async def test_update_child_at_max_limit():
    """Bug fix test: updating an existing child template when parent has max 5 children should work"""
    print("=" * 60)
    print("TEST 8: Update child at max 5 children (bugfix)")
    print("=" * 60)

    from app.routers.templates import create_template, update_template, delete_template, list_templates
    from app.models import TemplateCreate, TemplateUpdate, FieldDef

    parent = await create_template(TemplateCreate(
        name="Bugfix Parent",
        description="Test bugfix parent",
        fields=[
            FieldDef(name="header", length_rule="fixed", length_value=2, data_type="bytes"),
            FieldDef(name="body", length_rule="fixed", length_value=4, data_type="bytes"),
        ]
    ))
    print(f"✓ Created parent: id={parent.id}")

    child_ids = []
    for i in range(5):
        child = await create_template(TemplateCreate(
            name=f"Bugfix Child {i+1}",
            description=f"Test child {i+1}",
            fields=[
                FieldDef(name=f"extra{i}", length_rule="fixed", length_value=1, data_type="uint8")
            ],
            parent_template_id=parent.id
        ))
        child_ids.append(child.id)
    print(f"✓ Created 5 child templates (max allowed), child_ids={child_ids}")

    first_child_id = child_ids[0]
    try:
        await update_template(first_child_id, TemplateUpdate(
            description="Updated child description",
            fields=[
                FieldDef(name="extra0", length_rule="fixed", length_value=2, data_type="uint16_be"),
                FieldDef(name="new_field", length_rule="fixed", length_value=1, data_type="uint8"),
            ]
        ))
        print(f"✓ Successfully updated child {first_child_id} (parent at max 5) - BUG FIXED!")
    except HTTPException as e:
        print(f"✗ Failed to update child {first_child_id}: {e.detail}")
        raise

    all_templates = await list_templates(limit=200, offset=0)
    child_templates = [t for t in all_templates if t.parent_template_id == parent.id]
    for child in child_templates:
        await delete_template(child.id)
    await delete_template(parent.id)
    print("✓ Cleaned up test templates")

    print("✓ All update-at-max-limit tests passed\n")


async def test_migration_includes_versions():
    """Bug fix test: migration should include samples parsed with all versions, not just latest"""
    print("=" * 60)
    print("TEST 9: Migration includes all template versions (bugfix)")
    print("=" * 60)

    from app.routers.templates import (
        create_template, update_template, prepare_migration,
        execute_migration, get_migration_status
    )
    from app.routers.parse import parse_single
    from app.routers.samples import create_sample
    from app.models import (
        TemplateCreate, TemplateUpdate, FieldDef, SampleCreate,
        MigrationPrepareRequest, MigrationExecuteRequest
    )

    source = await create_template(TemplateCreate(
        name="Migration Source v1",
        description="Migration source template",
        fields=[
            FieldDef(name="magic", length_rule="fixed", length_value=2, data_type="bytes"),
            FieldDef(name="body", length_rule="fixed", length_value=4, data_type="bytes"),
        ]
    ))
    print(f"✓ Created source template v1: id={source.id}")

    target = await create_template(TemplateCreate(
        name="Migration Target",
        description="Migration target template",
        fields=[
            FieldDef(name="magic", length_rule="fixed", length_value=2, data_type="bytes"),
            FieldDef(name="body", length_rule="fixed", length_value=4, data_type="bytes"),
            FieldDef(name="crc", length_rule="fixed", length_value=2, data_type="bytes"),
        ]
    ))
    print(f"✓ Created target template: id={target.id}")

    hex_data = "aabb11223344"
    sample1 = await create_sample(SampleCreate(
        name="Sample parsed with v1",
        hex_data=hex_data,
        note="Parsed when source was v1"
    ))
    sample2 = await create_sample(SampleCreate(
        name="Sample parsed with v2",
        hex_data=hex_data,
        note="Parsed when source was v2"
    ))

    await parse_single(source.id, sample1.id, version=None, use_cache=False)
    print(f"✓ Parsed sample {sample1.id} with source v1 (version=1)")

    source_v2 = await update_template(source.id, TemplateUpdate(
        description="Source v2",
        fields=[
            FieldDef(name="magic", length_rule="fixed", length_value=2, data_type="bytes"),
            FieldDef(name="length", length_rule="fixed", length_value=1, data_type="uint8"),
            FieldDef(name="body", length_rule="ref", length_ref_field="length", data_type="bytes"),
        ]
    ))
    print(f"✓ Updated source to v{source_v2.version}")

    hex_data_v2 = "aabb0411223344"
    sample2_v2 = await create_sample(SampleCreate(
        name="Sample parsed with v2 data",
        hex_data=hex_data_v2,
        note="Parsed when source was v2"
    ))

    await parse_single(source.id, sample2.id, version=None, use_cache=False)
    await parse_single(source.id, sample2_v2.id, version=None, use_cache=False)
    print(f"✓ Parsed {sample2.id}, {sample2_v2.id} with source v2 (version=2)")

    prep = await prepare_migration(MigrationPrepareRequest(
        source_template_id=source.id,
        target_template_id=target.id
    ))
    print(f"✓ Migration prepared: marked={prep.total_samples_marked} samples "
          f"(expected >= 3, should include v1 and v2 parsed samples)")

    assert prep.total_samples_marked >= 3, (
        f"Migration should include samples from v1 and v2, "
        f"but only marked {prep.total_samples_marked}"
    )
    print("✓ Migration correctly marked samples from ALL versions - BUG FIXED!")

    status = await get_migration_status(prep.migration_task_id)
    exec_result = await execute_migration(MigrationExecuteRequest(
        migration_task_id=prep.migration_task_id
    ))
    print(f"✓ Migration executed: success={exec_result.success_count}, "
          f"failed={exec_result.failed_count}, skipped={exec_result.skipped_count}")

    print("✓ All migration-version tests passed\n")


async def main():
    print("\n" + "=" * 60)
    print("TEMPLATE INHERITANCE & DIFF MERGE MODULE - TEST SUITE")
    print("=" * 60 + "\n")

    start_time = datetime.now()

    try:
        await test_database()
        parent_id, child_id = await test_template_inheritance()
        await test_inheritance_constraints(parent_id)
        await test_delete_protection(parent_id, child_id)
        a_id, b_id = await test_template_diff()
        p_id, c_id, s_id = await test_parse_with_inheritance()
        await test_batch_migration(p_id, c_id, s_id)
        await test_update_child_at_max_limit()
        await test_migration_includes_versions()

        elapsed = (datetime.now() - start_time).total_seconds()
        print("=" * 60)
        print(f"ALL TESTS PASSED in {elapsed:.2f} seconds!")
        print("=" * 60)
        return 0
    except Exception as e:
        elapsed = (datetime.now() - start_time).total_seconds()
        print(f"\n✗ TEST FAILED after {elapsed:.2f} seconds")
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
