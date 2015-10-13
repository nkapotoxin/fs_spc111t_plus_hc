import sqlalchemy as sql


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    user_table = sql.Table('user', meta, autoload=True)
    wrong_times = sql.Column('wrong_times', sql.String(64),default='0')
    user_table.create_column(wrong_times)
    last_error_time = sql.Column('last_error_time', sql.String(64),default='')
    user_table.create_column(last_error_time)


def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    user_table = sql.Table('user', meta, autoload=True)
    user_table.drop_column('wrong_times')
    user_table.drop_column('last_error_time')