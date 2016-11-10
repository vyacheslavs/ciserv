# -*- coding: utf-8 -*-

import sqlite3
import os.path

from config import config

conn=None

def check_db():
    if not os.path.isfile(config['CONFIG_FILE']):
        conn = sqlite3.connect(config['CONFIG_FILE'])
        c = conn.cursor()
        c.execute('CREATE TABLE kp_settings (name text, value text)')
        conn.commit()
        c.execute('CREATE TABLE kp_secrets (login text, pw text, kp_url text, kp_submit_url text)')
        conn.commit()

def store_key(k):
    c = conn.cursor()
    c.execute('''DELETE FROM kp_settings WHERE name="key"''')
    conn.commit()
    c.execute('INSERT INTO kp_settings VALUES (?,?)', ('key',k) )
    conn.commit()

def load_key():
    c = conn.cursor()
    c.execute('SELECT value FROM kp_settings WHERE name="key"')
    r = c.fetchone()
    if r == None:
        return None
    return r[0]

def store_secret(l,p,u,s):
    c = conn.cursor()
    c.execute('INSERT INTO kp_secrets VALUES (?,?,?,?)',(l,p,u,s))
    conn.commit()

def load_secrets(u,s):
    c = conn.cursor()
    c.execute('SELECT login, pw, kp_url, kp_submit_url FROM kp_secrets')

    res = []

    while True:
        r = c.fetchone()
        if r == None:
            break

        get = False

        db_url = r[2]
        scheme, rest = db_url.split('://', 1)
        path_elements = rest.split('/')

        while path_elements:
            url = '%s://%s' % (scheme, '/'.join(path_elements))
            # print "check", url,"..."

            if url == u:
                get = True
                # print "found match!!!!"

            path_elements.pop()

        if get:
            res.append(r)

    return res

check_db()
conn = sqlite3.connect(config['CONFIG_FILE'])

