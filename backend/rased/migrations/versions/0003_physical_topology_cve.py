"""physical topology (SNMP/LLDP) and CVE vulnerability intelligence

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-04 13:30:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

import rased.models

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    op.create_table(
        "physical_links",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("local_asset_id", sa.Integer(), nullable=False),
        sa.Column("local_port", sa.String(length=128), nullable=False),
        sa.Column("remote_asset_id", sa.Integer(), nullable=True),
        sa.Column("remote_chassis_id", sa.String(length=128), nullable=False),
        sa.Column("remote_sysname", sa.String(length=253), nullable=False),
        sa.Column("remote_port", sa.String(length=128), nullable=False),
        sa.Column("remote_descr", sa.String(length=256), nullable=False),
        sa.Column("source", sa.String(length=8), nullable=False),
        sa.Column("vlan", sa.Integer(), nullable=True),
        sa.Column("credential_id", sa.Integer(), nullable=True),
        sa.Column("first_seen", rased.models.UTCDateTime(timezone=True), nullable=False),
        sa.Column("last_seen", rased.models.UTCDateTime(timezone=True), nullable=False),
        sa.CheckConstraint("source IN ('lldp','cdp','fdb')", name=op.f("ck_physical_links_source_valid")),
        sa.ForeignKeyConstraint(["credential_id"], ["credentials.id"],
                                name=op.f("fk_physical_links_credential_id_credentials"), ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["local_asset_id"], ["assets.id"],
                                name=op.f("fk_physical_links_local_asset_id_assets"), ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["remote_asset_id"], ["assets.id"],
                                name=op.f("fk_physical_links_remote_asset_id_assets"), ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_physical_links")),
        sa.UniqueConstraint("local_asset_id", "local_port", "remote_chassis_id", "remote_port", "source",
                            name="uq_physical_links_edge"),
    )
    op.create_index(op.f("ix_physical_links_local_asset_id"), "physical_links", ["local_asset_id"], unique=False)

    op.create_table(
        "cve_entries",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("description_ar", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("cvss_score", sa.Float(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("published", sa.String(length=32), nullable=True),
        sa.Column("affected", _JSON, nullable=False),
        sa.Column("references", _JSON, nullable=False),
        sa.Column("imported_at", rased.models.UTCDateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_cve_entries")),
    )
    op.create_index(op.f("ix_cve_entries_cve_id"), "cve_entries", ["cve_id"], unique=True)
    op.create_index("ix_cve_entries_severity", "cve_entries", ["severity"], unique=False)

    op.create_table(
        "asset_vulnerabilities",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("asset_id", sa.Integer(), nullable=False),
        sa.Column("service_id", sa.Integer(), nullable=True),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("product", sa.String(length=128), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=True),
        sa.Column("matched_on", sa.String(length=128), nullable=False),
        sa.Column("cvss_score", sa.Float(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("first_seen", rased.models.UTCDateTime(timezone=True), nullable=False),
        sa.Column("last_seen", rased.models.UTCDateTime(timezone=True), nullable=False),
        sa.CheckConstraint("status IN ('open','resolved','false_positive')",
                           name=op.f("ck_asset_vulnerabilities_status_valid")),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"],
                                name=op.f("fk_asset_vulnerabilities_asset_id_assets"), ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["service_id"], ["services.id"],
                                name=op.f("fk_asset_vulnerabilities_service_id_services"), ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_asset_vulnerabilities")),
        sa.UniqueConstraint("asset_id", "service_id", "cve_id", name="uq_asset_vuln"),
    )
    op.create_index(op.f("ix_asset_vulnerabilities_asset_id"), "asset_vulnerabilities", ["asset_id"], unique=False)
    op.create_index(op.f("ix_asset_vulnerabilities_cve_id"), "asset_vulnerabilities", ["cve_id"], unique=False)
    op.create_index("ix_asset_vuln_severity", "asset_vulnerabilities", ["severity"], unique=False)

    # Widen credentials.kind to allow SNMP accounts (community / v3) used for physical topology.
    if op.get_bind().dialect.name == "postgresql":
        op.drop_constraint("kind_valid", "credentials", type_="check")
        op.create_check_constraint("kind_valid", "credentials", "kind IN ('winrm','ssh','snmp')")
    else:
        # In batch mode the metadata naming convention (ck_%(table_name)s_%(constraint_name)s)
        # is applied to the logical name, so pass "kind_valid", not the full constraint name.
        with op.batch_alter_table("credentials", schema=None) as batch_op:
            batch_op.drop_constraint("kind_valid", type_="check")
            batch_op.create_check_constraint("kind_valid", "kind IN ('winrm','ssh','snmp')")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.drop_constraint("kind_valid", "credentials", type_="check")
        op.create_check_constraint("kind_valid", "credentials", "kind IN ('winrm','ssh')")
    else:
        with op.batch_alter_table("credentials", schema=None) as batch_op:
            batch_op.drop_constraint("kind_valid", type_="check")
            batch_op.create_check_constraint("kind_valid", "kind IN ('winrm','ssh')")

    op.drop_index("ix_asset_vuln_severity", table_name="asset_vulnerabilities")
    op.drop_index(op.f("ix_asset_vulnerabilities_cve_id"), table_name="asset_vulnerabilities")
    op.drop_index(op.f("ix_asset_vulnerabilities_asset_id"), table_name="asset_vulnerabilities")
    op.drop_table("asset_vulnerabilities")
    op.drop_index("ix_cve_entries_severity", table_name="cve_entries")
    op.drop_index(op.f("ix_cve_entries_cve_id"), table_name="cve_entries")
    op.drop_table("cve_entries")
    op.drop_index(op.f("ix_physical_links_local_asset_id"), table_name="physical_links")
    op.drop_table("physical_links")
