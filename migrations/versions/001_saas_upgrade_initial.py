"""saas-upgrade initial schema

Revision ID: 001saasupgrade
Revises:
Create Date: 2025-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '001saasupgrade'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())

    if 'cafes' not in existing:
        op.create_table(
            'cafes',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('name', sa.Text, nullable=False, server_default=''),
            sa.Column('slug', sa.Text, unique=True, nullable=True),
            sa.Column('is_active', sa.Boolean, nullable=False, server_default='true'),
            sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        )

    if 'owners' not in existing:
        op.create_table(
            'owners',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('username', sa.Text, unique=True, nullable=False),
            sa.Column('email', sa.Text, unique=True, nullable=True),
            sa.Column('password_hash', sa.Text, nullable=False),
            sa.Column('cafe_name', sa.Text, server_default=''),
            sa.Column('cafe_id', sa.Integer, sa.ForeignKey('cafes.id'), nullable=True),
            sa.Column('google_place_id', sa.Text, server_default=''),
            sa.Column('is_active', sa.Boolean, nullable=False, server_default='true'),
            sa.Column('is_superadmin', sa.Boolean, nullable=False, server_default='false'),
            sa.Column('totp_secret', sa.Text, nullable=True),
            sa.Column('totp_enabled', sa.Boolean, server_default='false'),
            sa.Column('phone', sa.Text, server_default=''),
            sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
    else:
        cols = {c['name'] for c in inspector.get_columns('owners')}
        if 'is_superadmin' not in cols:
            op.add_column('owners', sa.Column('is_superadmin', sa.Boolean, nullable=False, server_default='false'))
        if 'totp_secret' not in cols:
            op.add_column('owners', sa.Column('totp_secret', sa.Text, nullable=True))
        if 'totp_enabled' not in cols:
            op.add_column('owners', sa.Column('totp_enabled', sa.Boolean, server_default='false'))
        if 'phone' not in cols:
            op.add_column('owners', sa.Column('phone', sa.Text, server_default=''))
        if 'cafe_id' not in cols:
            op.add_column('owners', sa.Column('cafe_id', sa.Integer, nullable=True))

    if 'cafe_tables' not in existing:
        op.create_table(
            'cafe_tables',
            sa.Column('id', sa.Text, primary_key=True),
            sa.Column('name', sa.Text, nullable=False),
            sa.Column('owner_id', sa.Integer, sa.ForeignKey('owners.id', ondelete='CASCADE'), nullable=True),
            sa.Column('cafe_id', sa.Integer, sa.ForeignKey('cafes.id'), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        )

    if 'menus' not in existing:
        op.create_table(
            'menus',
            sa.Column('owner_id', sa.Integer, sa.ForeignKey('owners.id', ondelete='CASCADE'), primary_key=True),
            sa.Column('cafe_id', sa.Integer, sa.ForeignKey('cafes.id'), nullable=True),
            sa.Column('data', sa.JSON, nullable=False, server_default='{"categories": []}'),
        )

    if 'ingredients' not in existing:
        op.create_table(
            'ingredients',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('owner_id', sa.Integer, sa.ForeignKey('owners.id', ondelete='CASCADE'), nullable=False),
            sa.Column('cafe_id', sa.Integer, sa.ForeignKey('cafes.id'), nullable=True),
            sa.Column('name', sa.Text, nullable=False),
            sa.Column('unit', sa.Text, server_default='unit'),
            sa.Column('stock', sa.Numeric(10, 3), server_default='0'),
            sa.Column('low_stock_threshold', sa.Numeric(10, 3), server_default='5'),
            sa.Column('menu_item_id', sa.Text, nullable=True),
            sa.Column('qty_per_order', sa.Numeric(10, 3), server_default='1'),
            sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        )

    if 'orders' not in existing:
        op.create_table(
            'orders',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('owner_id', sa.Integer, sa.ForeignKey('owners.id'), nullable=True),
            sa.Column('cafe_id', sa.Integer, sa.ForeignKey('cafes.id'), nullable=True),
            sa.Column('table_id', sa.Text, nullable=True),
            sa.Column('table_name', sa.Text, nullable=True),
            sa.Column('customer_name', sa.Text, server_default='Guest'),
            sa.Column('customer_email', sa.Text, server_default=''),
            sa.Column('customer_phone', sa.Text, server_default=''),
            sa.Column('items', sa.JSON, nullable=False, server_default='[]'),
            sa.Column('modifiers', sa.JSON, nullable=True),
            sa.Column('subtotal', sa.Numeric(10, 2), server_default='0'),
            sa.Column('tip', sa.Numeric(10, 2), server_default='0'),
            sa.Column('total', sa.Numeric(10, 2), server_default='0'),
            sa.Column('status', sa.Text, server_default='pending'),
            sa.Column('pickup_code', sa.Text, server_default=''),
            sa.Column('origin', sa.Text, server_default='table'),
            sa.Column('notes', sa.Text, server_default=''),
            sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
    else:
        cols = {c['name'] for c in inspector.get_columns('orders')}
        if 'pickup_code' not in cols:
            op.add_column('orders', sa.Column('pickup_code', sa.Text, server_default=''))
        if 'customer_phone' not in cols:
            op.add_column('orders', sa.Column('customer_phone', sa.Text, server_default=''))
        if 'modifiers' not in cols:
            op.add_column('orders', sa.Column('modifiers', sa.JSON, nullable=True))
        if 'notes' not in cols:
            op.add_column('orders', sa.Column('notes', sa.Text, server_default=''))
        if 'cafe_id' not in cols:
            op.add_column('orders', sa.Column('cafe_id', sa.Integer, nullable=True))
        if 'updated_at' not in cols:
            op.add_column('orders', sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True))

    if 'feedback' not in existing:
        op.create_table(
            'feedback',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('owner_id', sa.Integer, sa.ForeignKey('owners.id'), nullable=True),
            sa.Column('cafe_id', sa.Integer, sa.ForeignKey('cafes.id'), nullable=True),
            sa.Column('order_id', sa.Integer, sa.ForeignKey('orders.id'), nullable=True),
            sa.Column('table_id', sa.Text, nullable=True),
            sa.Column('customer_name', sa.Text, server_default='Guest'),
            sa.Column('rating', sa.Integer, nullable=False),
            sa.Column('comment', sa.Text, server_default=''),
            sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
    else:
        cols = {c['name'] for c in inspector.get_columns('feedback')}
        if 'order_id' not in cols:
            op.add_column('feedback', sa.Column('order_id', sa.Integer, nullable=True))
        if 'cafe_id' not in cols:
            op.add_column('feedback', sa.Column('cafe_id', sa.Integer, nullable=True))

    if 'remember_tokens' not in existing:
        op.create_table(
            'remember_tokens',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('owner_id', sa.Integer, sa.ForeignKey('owners.id', ondelete='CASCADE'), nullable=True),
            sa.Column('token_hash', sa.Text, unique=True, nullable=False),
            sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        )

    if 'settings' not in existing:
        op.create_table(
            'settings',
            sa.Column('owner_id', sa.Integer, sa.ForeignKey('owners.id', ondelete='CASCADE'), primary_key=True),
            sa.Column('logo_url', sa.Text, server_default=''),
            sa.Column('brand_color', sa.Text, server_default='#4f46e5'),
            sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        )


def downgrade():
    pass
