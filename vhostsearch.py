#!/usr/bin/env python
# current version is slow as no threads are used
# so it is not made for checking whole /8 ranges
# it is quite ok for quick /24 check


import os
import ssl
import sys
import time
import socket
import requests
import argparse
from IPython import embed

__tool_version__ = '0.1'
__tool_author__ = 'dash'

def get_session(ip,port,vhost,sslOn,sockTimeout):
    ''' 
    '''
    print("-"*80)

# nah we want to read it directly and not unpack it first
#Accept-Encoding: gzip, deflate\r\n\

    my_req='GET / HTTP/1.1\r\n\
Host: {0}\r\n\
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0\r\n\
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n\
Accept-Language: en-US,en;q=0.5\r\n\
DNT: 1\r\n\
Connection: close\r\n\
Upgrade-Insecure-Requests: 1\r\n\
Sec-GPC: 1\r\n\
\r\n\
\r\n'.format(vhost)

    if not sslOn:

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(sockTimeout)
            sock.connect((ip,port))

            my_req = my_req.encode()
            sock.send(my_req)
            data = sock.recv(4096)
            print("[+] IP {0}:{1} with VHOST: {2} SSL: {3} DATA: {4}".format(ip,port,vhost,sslOn,data))

        except ConnectionRefusedError as e:
            print("[+] IP {0}:{1} with VHOST: {2} SSL: {3} DATA: {4}".format(ip,port,vhost,sslOn,e))
            return False
        except socket.timeout as e:
            print("[+] IP {0}:{1} with VHOST: {2} SSL: {3} DATA: {4}".format(ip,port,vhost,sslOn,e))
            return False
        except OSError as e:
            print("[+] IP {0}:{1} with VHOST: {2} SSL: {3} DATA: {4}".format(ip,port,vhost,sslOn,e))
            return False

    else:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.timeout=sockTimeout

        try:
            with socket.create_connection((ip, 443),sockTimeout) as sock:
                #sock.settimeout(5)
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    ssock.settimeout(sockTimeout)

                    my_req = my_req.encode()
                    ssock.send(my_req)
                    data = ssock.recv(4096)
                    print("[+] IP {0}:{1} with VHOST: {2} SSL: {3} DATA: {4}".format(ip,port,vhost,ssock.version(),data))
                    ssock.close()
                    sock.close()
        except ConnectionRefusedError as e:
            print("[+] IP {0}:{1} with VHOST: {2} SSL: {3} DATA: {4}".format(ip,port,vhost,sslOn,e))
            return False
        except socket.timeout as e:
            print("[+] IP {0}:{1} with VHOST: {2} SSL: {3} DATA: {4}".format(ip,port,vhost,sslOn,e))
            return False
        except OSError as e:
            print("[+] IP {0}:{1} with VHOST: {2} SSL: {3} DATA: {4}".format(ip,port,vhost,sslOn,e))
            return False

def run(args):

    ipRangeFile = args.ipRangeFile
    vhost = args.vhost
    sockTimeout = args.sockTimeout

    fr = open(ipRangeFile,'r')
    buf = fr.readlines()

    for ip in buf:
        ip = ip.rstrip('\r')
        ip = ip.rstrip('\n')

        # default SSL webserver
        content = get_session(ip,443,vhost,True,sockTimeout)

        # default NONE-SSL webserver
        content = get_session(ip,80,vhost,False, sockTimeout)

    # last line    
    print("-"*80)

def main():
    parser_desc = 'vhostsearch {0} by {1}'.format(__tool_version__,__tool_author__)
    prog_desc = 'this script has been written to find hosts hidden behind myracloud/cloudflare or others, it will ask webservers found in the defined range if the vhost is served by them'
    parser = argparse.ArgumentParser(prog = prog_desc, description=parser_desc)
    parser.add_argument("-z","--socket-timeout",action="store",required=False,type=int,help='time to wait for socket (default:5)',dest='sockTimeout',default=5)
#    parser.add_argument("-r","--ip-range",action="store",required=False,help='define ip range to check',dest='ipRange')
    parser.add_argument("-rf","--iprange-file",action="store",required=False,help='give file with ips, one per line',dest='ipRangeFile')
    parser.add_argument("-t","--vhost",action="store",required=False,help='search for this vhost',dest='vhost')
#    parser.add_argument("-tf","--vhost-file",action="store",required=False,help='search for vhosts in this file',dest='vhostFile')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit()

    args = parser.parse_args()
    run(args)

if __name__ == "__main__":
	main()
