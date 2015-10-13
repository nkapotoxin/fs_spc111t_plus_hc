# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import copy

from keystone.common import sql
from keystone import exception
from keystone.openstack.common import timeutils
from keystone import token
from keystone.token.backends import sql as token_sql
from keystone import config
import psycopg2
import psycopg2.extras
import passlib.hash
CONF = config.CONF

class Token(token_sql.Token):
    # Public interface
    TOKEN_NUM_FOR_NEW_LIST = 50

    def delete_tokens(self, user_id, tenant_id=None, trust_id=None,
                      consumer_id=None):
        """Deletes all tokens in one session

        The user_id will be ignored if the trust_id is specified. user_id
        will always be specified.
        If using a trust, the token's user_id is set to the trustee's user ID
        or the trustor's user ID, so will use trust_id to query the tokens.

        """
        TokenModel = token_sql.TokenModel
        session = sql.get_session()
        engine = sql.get_engine()
        with session.begin():
            now = timeutils.utcnow()
            if tenant_id is None and consumer_id is None:
                trust_cmd = "update token set valid = \'f\' where expires > \'%s\' and valid = \'t\' and trust_id = \'%s\';" % (now, trust_id)
                user_cmd = "update token set valid = \'f\' where expires > \'%s\' and valid = \'t\' and user_id = \'%s\';" % (now, user_id)
                if trust_id:
                    engine.execute(trust_cmd)
                else:
                    engine.execute(user_cmd)

            if tenant_id is not None:
                dataConnection = CONF.database.connection
                dataInfo = dataConnection.split('//')
                dataMsg = dataInfo[1].split(':')
                user_name = dataMsg[0]
                user_data = dataMsg[1].split('@')
                user_password = user_data[0]
                connectData = user_data[1].split(':')
                dataIp = connectData[0]
                dataPort = dataMsg[2].split('/')[0]
                connection = psycopg2.connect(host=dataIp, port=dataPort, user=user_name, password=user_password, database='keystone')
                cursor = connection.cursor(cursor_factory=psycopg2.extras.DictCursor)
                if user_id is None:
                    object = "update token set valid = \'f\' where valid = 't' and expires > \'" + str(now) + "\'" + \
                          "and extra like \'%"  + tenant_id + '%\';'
                    cursor.execute(object)
                    connection.commit()
                elif  self._count_tokens_for_user(user_id = user_id) > self.TOKEN_NUM_FOR_NEW_LIST:
                    object = "update token set valid = \'f\' where valid = 't' and expires > \'" + str(now) + "\'" + \
                             " and user_id = \'" + str(user_id) + "\'" + " and extra like \'%"  + tenant_id + '%\';'
                    cursor.execute(object)
                    connection.commit()
                else:
                    super(Token, self).delete_tokens(user_id, tenant_id = tenant_id)

                connection.close()

            if consumer_id is not None:
                query = session.query(TokenModel)
                query = query.filter_by(valid=True)
                query = query.filter(TokenModel.expires > now)
                if trust_id:
                    query = query.filter(TokenModel.trust_id == trust_id)
                else:
                    query = query.filter(TokenModel.user_id == user_id)
                for token_ref in query.all():
                    token_ref_dict = token_ref.to_dict()
                    if not self._consumer_matches(consumer_id, token_ref_dict):
                        continue
                    token_ref.valid = False
                    
            session.flush()

    def _list_tokens_for_trust(self, trust_id):
        session = sql.get_session()
        now = timeutils.utcnow()
        TokenModel = token_sql.TokenModel
        query = session.query(TokenModel.id)
        token_references = query.filter(TokenModel.expires > now
                                        , TokenModel.trust_id == trust_id
                                        , TokenModel.valid == True)
        tokens = [x[0] for x in token_references]
        return tokens

    def _list_tokens_for_user(self, user_id, tenant_id=None):
        session = sql.get_session()
        now = timeutils.utcnow()
        TokenModel = token_sql.TokenModel
        query = session.query(TokenModel.id)

        statement_expires = "expires > '{time}'".format(time = now)
        statement_user_id = "user_id = '{user_id}'".format(user_id = user_id)
        statement_valid = "valid = True"
        statement_tenant_id = "extra LIKE '%{tenant_id}%'".format(tenant_id = tenant_id)
        token_references = query.filter(statement_expires + " AND " + statement_valid + " AND " + statement_user_id)

        if tenant_id is not None and token_references.count() > self.TOKEN_NUM_FOR_NEW_LIST:
            token_references = token_references.filter(statement_tenant_id)
            tokens = [x[0] for x in token_references]
        else:
            tokens = super(Token, self)._list_tokens_for_user(user_id, tenant_id = tenant_id)
        return tokens

    def _count_tokens_for_user(self, user_id):
        session = sql.get_session()
        now = timeutils.utcnow()
        TokenModel = token_sql.TokenModel
        query = session.query(TokenModel)

        return query.filter(TokenModel.expires > now
                                        , TokenModel.valid == True
                                        , TokenModel.user_id == user_id).count()
