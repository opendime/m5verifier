#!/usr/bin/env python
#
# Python 2&3 code to check we are a legit Opendime.
#
from __future__ import print_function
try:
    input = raw_input
    B2A = lambda x:x
    A2B = lambda x:x.encode('ascii')
except NameError:
    # Py3
    B2A = lambda x: str(x, 'ascii')
    A2B = lambda x: bytes(x, 'ascii')

import os, sys, json, time, subprocess
from hashlib import sha256
from binascii import a2b_hex, b2a_hex
from base64 import b64encode

# See: https://github.com/richardkiss/pycoin
#load_remote_module('pycoin')
#from pycoin.contrib import msg_signing as MS
import ecdsa

ADV = lambda path, fn: fn

def fail(msg):
    print("\n" + '*'*48)
    print("FAIL FAIL FAIL -- Do Not Trust -- FAIL FAIL FAIL")
    print('*'*48 + '\n')

    print('PROBLEM: ' + msg)
    sys.exit(1)

def doit():
    path = None
    expect = json.load(open('variables.json'))

    chain = ADV(path, 'chain.crt')
    unit = ADV(path, 'unit.crt')
    x = B2A(subprocess.check_output(['openssl', 'verify', '-CAfile', chain, unit ]))
    if not x.endswith('unit.crt: OK\n'):
        fail("Factory certificate failed verify by Openssl!")

    x = subprocess.check_output(['openssl', 'x509', '-in', chain, '-noout', '-fingerprint' ])
    if b'A1:02:01:E3:02:0E:C9:6B:30:90:62:69:CD:E3:6F:82:80:35:A9:8B' not in x:
        fail("Factory certificate is wrong.")

    x = subprocess.check_output(['openssl', 'x509', '-in', unit, '-noout', '-subject' ])
    subj = B2A(x).split('/')[1]
    if subj != 'serialNumber=' + expect['sn'] + '+' + expect['ae']:
        fail("Certificate is for some other unit: " + subj)

    from ecdsa import VerifyingKey

    x = subprocess.check_output(['openssl', 'x509', '-in', unit, '-noout', '-pubkey' ])
    pubkey = VerifyingKey.from_pem(B2A(x))

    my_nonce = a2b_hex('3bb5c57d26a8a6f5ca654aab9b0fd780132a3ef7')
    ae_nonce = a2b_hex('7a65ba5f1012e9a3dae95c78c12ee68124050727f0e0e273dea8249ea2899c4e')
    sig = a2b_hex('ce5d72803c3bfc049b13825180fbdc41f45bf2c57bb13542fd1a94a4593ec04d77fc5d41d6c22aaa1feb1afa89bef5adab8d44ac773d163b3eff6c5a576690bd')

    ok = verify_ae_signature(pubkey, expect, my_nonce, ae_nonce, sig)

    if not ok:
        fail("Incorrect signature in anti-counterfeiting test!")
    else:
        print("Pass Verify")

def verify_ae_signature(pubkey, expect, my_nonce, ae_nonce, sig):
    H = lambda x: sha256(x).digest()
    H2 = lambda x: '%s (l=%d)' % (sha256(x).hexdigest(), len(x))

    if 'ad' in expect:
        slot13 = A2B(expect['ad'].ljust(72))[0:32]
        lock = b'\0'
    else:
        slot13 = b'\xff' * 32
        lock = b'\1'

    slot14 = A2B(expect['sn'] + "+" + expect['ae'])[0:32]

    print('m1tail = %s' % H2(ae_nonce + my_nonce + b'\x16\0\0'))

    fixed = b'\x00\xEE\x01\x23' + b'\0' *25
    msg1 = slot14 + b'\x15\x02\x0e' + fixed + H(ae_nonce + my_nonce + b'\x16\0\0')
    print('msg1 = %s' % H2(msg1))

    msg2 = slot13 + b'\x15\x02\x0d' + fixed + H(msg1)
    SN = a2b_hex(expect['ae'])

    print('msg2 = %s' % H2(msg2))

    body = H(msg2) + b'\x41\x40\x00\x00\x00\x00\x3c\x00\x2d\0\0\xEE' \
                + SN[2:6] + b'\x01\x23'+ SN[0:2] + lock + b'\0\0'

    print('final = %s' % H2(body))

    from ecdsa.keys import BadSignatureError
    try:
        ok = pubkey.verify(sig, body, hashfunc=sha256)
    except BadSignatureError:
        ok = False

    return ok

    
if __name__ == '__main__':
    doit()
