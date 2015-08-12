import hashlib
import base64
import copy

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
