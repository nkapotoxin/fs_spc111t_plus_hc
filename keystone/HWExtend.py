import re
import base64
import hashlib
from keystone import exception
from keystone.common import sql
from keystone.openstack.common import timeutils

REVOKE_TOKEN_FILE = "/var/log/fusionsphere/component/keystone/revoke_token.log"

class ValidationPasswordError(exception.Error):
    code = 400
    title = 'Bad Request'

#security: validate input password
def validatePassword(user_name, password):
    if password is None:
        return
    if not password:
        raise ValidationPasswordError("Blank password is not allow")
    if len(password) < 8:
        raise ValidationPasswordError("Password should contain at least 8 characters")
    if user_name == password:
        raise ValidationPasswordError("Password should not equal to user name")
    if user_name == password[::-1]:
        raise ValidationPasswordError("Password should not equal to reversed user name")
    #digit
    digitPattern = "\d+"
    digitMatch = 1 if len(re.findall(digitPattern, password)) > 0 else 0
    #low char
    lowcharPattern = "[a-z]"
    lowcharMatch = 1 if len(re.findall(lowcharPattern, password)) > 0 else 0
    #up char
    upcharPattern = "[A-Z]"
    upcharMatch = 1 if len(re.findall(upcharPattern, password)) > 0 else 0
    #other
    otherPattern = "\W+"
    otherMatch = 1 if len(re.findall(otherPattern, password)) > 0 else 0
    if otherMatch == 0 and password.find("_") != -1:
        otherMatch = 1
    typeCount = digitMatch + lowcharMatch + upcharMatch + otherMatch

    if typeCount < 3:
        raise ValidationPasswordError("Password should at least contain three types of characters")

#security: check password when create user
def checkOnCreate(function):
    def inner(self, user_ref):
        #check if input password is validate
        userdata = user_ref.copy()
        user_name = userdata.get('name', None)
        password = userdata.get("password", None)
        validatePassword(user_name, password)
        #call update user
        return function(self, user_ref)
    return inner

#security: check password when update user
def checkOnUpdate(function):
    def inner(self, user_id, user_ref):
        #check if input password is validate
        if user_ref.has_key("password"):
            session = sql.get_session()
            old_user_ref = self.driver._get_user(session, user_id)
            old_user_dict = old_user_ref.to_dict()
            user_name = old_user_dict.get('name', None)
            password = user_ref.get("password", None)
            if self.driver._check_password(password, old_user_ref):
                raise ValidationPasswordError("New password should not be the same as the original password")
            else:
                validatePassword(user_name, password)
        #call update user
        return function(self, user_id, user_ref)
    return inner

#security: save revoke token before delete
def saveRevokeToken(TokenModel):
    def outer(function):
        def inner(self):
            #save revoke token to log file
            session = self.get_session()
            tokens = []
            query = session.query(TokenModel.id, TokenModel.expires)
            token_references = query.filter(TokenModel.expires < timeutils.utcnow())
            for token_ref in token_references:
                record = {
                    'id': token_ref[0],
                    'expires': token_ref[1],
                }
                tokens.append(record)
    
            try:
                with open(REVOKE_TOKEN_FILE, "a+") as f:
                    for token in tokens:
                        f.write(token.get('id') + "\n")
                import os
                import stat
                os.chmod(REVOKE_TOKEN_FILE, stat.S_IREAD | stat.S_IWRITE | stat.S_IRGRP)
            except Exception, e:
                print("save revoke token fail:" + str(e))
            #delete revoke token
            function(self)
        return inner
    return outer

#change PKI id to UUID
def pkiToUuid(token):
    if token is None:
        return "None"
    if token[:2] == "MI":
        hasher = hashlib.md5()
        hasher.update(token)
        token = hasher.hexdigest()
    return token

#encode token to a partial base64 string.
def b64encodeToken(token):
    return "encode-" + base64.encodestring(pkiToUuid(token))[:32]

def hasSensitiveStr(inStr):
    sensitiveStr = ['Password','PASSWORD','password','Pswd','PSWD','signature','HmacSHA256']
    for item in sensitiveStr:
        if item in str(inStr):
            return True;
        
    return False
