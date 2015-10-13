import sqlalchemy as sql
from sqlalchemy.orm import sessionmaker

def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    token_table = sql.Table('token', meta, autoload=True)
    token_table.c.id.alter(type=sql.String(640))


def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    user_table = sql.Table('token', meta, autoload=True)
    if migrate_engine.name != 'mysql':
        # NOTE(aloga): sqlite does not enforce length on the
        # VARCHAR types: http://www.sqlite.org/faq.html#q9
        # postgresql and DB2 do not truncate.
        maker = sessionmaker(bind=migrate_engine)
        session = maker()
        for user in session.query(user_table).all():
            values = {'id': user.id[:64]}
            update = (user_table.update().
                      where(user_table.c.id == user.id).
                      values(values))
            migrate_engine.execute(update)

        session.commit()
        session.close()
    user_table.c.id.alter(type=sql.String(64))