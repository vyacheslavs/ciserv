
# d8312a59523d3c37d6a5401d3cfddd077e194680

from flask import Flask
from flask import request
import json
import db
import os
import logging
from nonce import Nonce, Key, Verifier, verify, sign, decrypt, encrypt
from random import randint
from config import config
from logging.handlers import RotatingFileHandler

def test_assoc():
    err = {}

    key = db.load_key()

    err["Count"]=None
    err["Entries"]=None
    err["Error"]=""
    err["Hash"]="d8312a59523d3c37d6a5401d3cfddd077e194680"
    err["Id"]=""
    err["Nonce"]=""
    err["RequestType"]="test-associate"
    err["Success"]=False
    err["Verifier"]=""
    err["Version"]="1.8.4.1"
    err["objectName"]=""

    if key != None:
        n = Nonce()
        k = Key(key)
        err["Nonce"] = n.b64()
        err["Verifier"] = sign(n, k).b64()
        err["Id"]=config['ID']
        err["TriggerUnlock"] = False
        err["Success"]=True

    errs = json.dumps(err)

    return errs

def assoc(req):

    if not req.has_key("Key"):
        return "No Key"

    # db.store_key(req["Key"])

    key = Key(req["Key"])
    n = Nonce(req["Nonce"])
    verifier = Verifier(req["Verifier"])

    if not verify(n, verifier, key):
        return "Not verified"

    n = Nonce()
    new_v = sign(n, key)

    resp = {}
    resp["Count"]=None
    resp["Entries"]=None
    resp["Error"]=""
    resp["Hash"]="d8312a59523d3c37d6a5401d3cfddd077e194680"
    resp["Id"]=config['ID']

    resp["Nonce"] = n.b64()
    resp["RequestType"] = "associate"
    resp["Success"] = False
    resp["Verifier"] = new_v.b64()
    resp["Version"] = "1.8.4.1"
    resp["objectName"] = ""

    resps = json.dumps(resp)
    return resps

def set_login(req):

    if not req.has_key("Nonce"):
        return "No nonce"

    k64 = db.load_key()
    if not k64:
        return "No loaded key"
    key = Key(k64)
    n = Nonce(req["Nonce"])

    login = decrypt(n, key, req["Login"])
    pw = decrypt(n, key, req["Password"])
    url = decrypt(n, key, req["Url"])
    surl = decrypt(n, key, req["SubmitUrl"])

    db.store_secret(login,pw,url,surl)

    resp={}
    resp["Count"] = None
    resp["Entries"] = None
    resp["Error"] = ""
    resp["Hash"] = "d8312a59523d3c37d6a5401d3cfddd077e194680"
    resp["Id"] = config['ID']

    n = Nonce()
    resp["Nonce"] = n.b64()
    resp["RequestType"] = "set-login"
    resp["Success"] = True
    v = sign(n, key)
    resp["Verifier"] = v.b64()
    resp["Version"] = "1.8.4.1"
    resp["objectName"] = ""

    resps = json.dumps(resp)
    return resps


def get_logins(req):
    if not req.has_key("Nonce"):
        return "No nonce"

    k64 = db.load_key()
    if not k64:
        return "No loaded key"
    key = Key(k64)
    n = Nonce(req["Nonce"])

    url = decrypt(n, key, req["Url"])
    surl = decrypt(n, key, req["SubmitUrl"])

    sec = db.load_secrets(url, surl)

    resp={}
    resp["Count"] = len(sec)

    n = Nonce()

    entries = []
    for idx in sec:
        item = {}

        item["Login"] = encrypt(n, key, idx[0])
        item["Password"] = encrypt(n, key, idx[1])
        item["Name"] = encrypt(n, key, 'credentials for '+url)
        item["StringFields"] = None
        item["Uuid"] = encrypt(n, key, 'UUID')

        entries.append(item)

    resp["Entries"] = entries

    if len(entries) == 0:
        resp["Entries"] = None
        resp["Count"] = None

    resp["Error"] = ""
    resp["Hash"] = "d8312a59523d3c37d6a5401d3cfddd077e194680"
    resp["Id"] = config['ID']

    resp["Nonce"] = n.b64()
    resp["RequestType"] = "get-logins"
    resp["Success"] = True
    v = sign(n, key)
    resp["Verifier"] = v.b64()
    resp["Version"] = "1.8.4.1"
    resp["objectName"] = ""

    resps = json.dumps(resp)
    return resps

app = Flask(__name__)

#app.logger.warning('A warning occurred (%d apples)', 42)
#app.logger.error('An error occurred')
#app.logger.info('Info')

@app.route("/", methods=['POST'])
def main():

    handler = RotatingFileHandler('keepasserv.log', maxBytes=10000, backupCount=1)
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)

    log = logging.getLogger('werkzeug')
    log.setLevel(logging.DEBUG)
    log.addHandler(handler)

    req = json.loads(request.data)

    if not req.has_key("RequestType"):
        return "not implemented", 500

    if req["RequestType"] == "test-associate":
        return test_assoc()

    if req["RequestType"] == "associate":
        return assoc(req)

    if req["RequestType"] == "set-login":
        return set_login(req)

    if req["RequestType"] == "get-logins":
        return get_logins(req)

    return request.data

if __name__ == "__main__":
    app.run()
