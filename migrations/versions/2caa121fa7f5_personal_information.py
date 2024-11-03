"""personal information

Revision ID: 2caa121fa7f5
Revises: d8e629d75729
Create Date: 2024-10-18 09:29:26.748498

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '2caa121fa7f5'
down_revision = 'd8e629d75729'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('appointment', schema=None) as batch_op:
        batch_op.add_column(sa.Column('doctor_name', sa.String(length=150), nullable=False))
        batch_op.add_column(sa.Column('email', sa.String(length=150), nullable=False))
        batch_op.add_column(sa.Column('phone_number', sa.String(length=15), nullable=False))
        batch_op.add_column(sa.Column('address', sa.String(length=255), nullable=False))
        batch_op.add_column(sa.Column('age', sa.Integer(), nullable=False))
        batch_op.add_column(sa.Column('gender', sa.String(length=10), nullable=False))
        batch_op.add_column(sa.Column('blood_group', sa.String(length=5), nullable=False))
        batch_op.alter_column('appointment_date',
               existing_type=postgresql.TIMESTAMP(),
               type_=sa.Date(),
               existing_nullable=False)
        batch_op.drop_constraint('appointment_doctor_id_fkey', type_='foreignkey')
        batch_op.drop_column('doctor_id')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('appointment', schema=None) as batch_op:
        batch_op.add_column(sa.Column('doctor_id', sa.INTEGER(), autoincrement=False, nullable=False))
        batch_op.create_foreign_key('appointment_doctor_id_fkey', 'user', ['doctor_id'], ['id'])
        batch_op.alter_column('appointment_date',
               existing_type=sa.Date(),
               type_=postgresql.TIMESTAMP(),
               existing_nullable=False)
        batch_op.drop_column('blood_group')
        batch_op.drop_column('gender')
        batch_op.drop_column('age')
        batch_op.drop_column('address')
        batch_op.drop_column('phone_number')
        batch_op.drop_column('email')
        batch_op.drop_column('doctor_name')

    # ### end Alembic commands ###