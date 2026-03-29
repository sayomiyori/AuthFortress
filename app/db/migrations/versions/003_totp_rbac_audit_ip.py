"""totp fields, superadmin role data, audit ip_address

Revision ID: 003_totp
Revises: 002_oauth
Create Date: 2026-03-28

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "003_totp"
down_revision: Union[str, None] = "002_oauth"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("totp_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("users", sa.Column("backup_codes_hashed", sa.JSON(), nullable=True))
    op.add_column("users", sa.Column("totp_secret_encrypted", sa.String(length=512), nullable=True))
    op.drop_column("users", "totp_secret")

    op.add_column("audit_logs", sa.Column("ip_address", sa.String(length=64), nullable=True))
    op.execute(sa.text("UPDATE audit_logs SET ip_address = ip"))
    op.drop_column("audit_logs", "ip")


def downgrade() -> None:
    op.add_column("audit_logs", sa.Column("ip", sa.String(length=64), nullable=True))
    op.execute(sa.text("UPDATE audit_logs SET ip = ip_address"))
    op.drop_column("audit_logs", "ip_address")

    op.add_column("users", sa.Column("totp_secret", sa.String(length=64), nullable=True))
    op.drop_column("users", "totp_secret_encrypted")
    op.drop_column("users", "backup_codes_hashed")
    op.drop_column("users", "totp_enabled")
