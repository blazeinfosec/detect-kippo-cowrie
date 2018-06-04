#!/usr/bin/python3
# detectKippoCowrie.py
#
#
#
# by Julio Cesar Fort
# Copyright 2016-2018 Blaze Information Security

import sys
import socket
import time
import platform
import argparse

CRED = '\033[91m'
CEND = '\033[0m'

DEFAULT_BANNER = "SSH-2.0-OpenSSH_"
DEFAULT_KIPPOCOWRIE_BANNERS = ["SSH-2.0-OpenSSH_5.1p1 Debian-5", "SSH-1.99-OpenSSH_4.3", "SSH-1.99-OpenSSH_4.7",
                               "SSH-1.99-Sun_SSH_1.1", "SSH-2.0-OpenSSH_4.2p1 Debian-7ubuntu3.1",
                               "SSH-2.0-OpenSSH_4.3", "SSH-2.0-OpenSSH_4.6", "SSH-2.0-OpenSSH_5.1p1 Debian-5",
                               "SSH-2.0-OpenSSH_5.1p1 FreeBSD-20080901", "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu5",
                               "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu6", "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu7",
                               "SSH-2.0-OpenSSH_5.5p1 Debian-6", "SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze1",
                               "SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze2", "SSH-2.0-OpenSSH_5.8p2_hpn13v11 FreeBSD-20110503",
                               "SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1", "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",
                               "SSH-2.0-OpenSSH_5.9", "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"]

DEFAULT_PORT = 22
VERBOSE = True
ERROR = -1

def getSSHBanner(bannerFromServer):
    """
    This function receives the banner of the SSH server. It returns true if
    the server advertises itself as OpenSSH.
    """
    banner = bannerFromServer.decode('utf-8').strip()
    
    if banner in DEFAULT_KIPPOCOWRIE_BANNERS:
        print("[!] Heads up: the banner of this server is on Kippo/Cowrie's default list. May be promising...")
    
    return DEFAULT_BANNER in banner


def connectToSSH(host, port):
    try:
        socket.setdefaulttimeout(5)
        sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sockfd.connect((host, port))

        banner = sockfd.recv(1024)
        
        if getSSHBanner(banner):
            if VERBOSE:
                print("[+] %s:%d advertised itself as OpenSSH. Continuing..." % (host, port))
            else:
                printf("[!] %s:%d does not advertise itself as OpenSSH. Quitting..." % (host, port))
                return False

    except Exception as err:
        print("[!] Error connecting to %s port %d: %s" % (host, port, str(err)))
        return False
        
    return sockfd


def probeBadVersion(sockfd):
    try:
        sockfd.sendall('SSH-1337\n'.encode('utf-8'))
    except Exception as err:
        print("[!] Error sending probe #1: %s" % str(err))
    
    response = sockfd.recv(1024)
    sockfd.close()
    
    if VERBOSE:
        print(response)
    
    if b"bad version" in response:
        if VERBOSE:
            print("[*] Got 'bad version' in response to probe #1. Might be a honeypot!\n")
        return True
    else:
        return False


# this probe works against Cowrie, but also some misconfigured versions of OpenSSH 5.3
def probeSpacerPacketCorrupt(sockfd):
    try:
        sockfd.sendall("SSH-2.0-OpenSSH\n\n\n\n\n\n\n\n\n\n".encode('utf-8'))
    except Exception as err:
        print("[!] Error sending probe #2: %s" % str(err))
        
    response = sockfd.recv(1024)
    sockfd.close()
    
    if b"corrupt" in response or b"mismatch" in response:
        if VERBOSE:
            print("[*] Got 'packet corrupt' or 'protocol mismatch' in response of probe #2. Might be a honeypot!\n")
            return True
        else:
            return False



def probeDoubleBanner(sockfd):
    try:
        sockfd.sendall("SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2\nSSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2\n".encode('utf-8'))
    except Exception as err:
        print("[!] Error sending probe #3: %s" % str(err))
    
    response = sockfd.recv(1024)
    sockfd.close()

    if b"corrupt" in response or b"mismatch" in response:
        if VERBOSE:
            print("[*] Got 'packet corrupt' or 'protocol mismatch' in response of probe #3. Might be a honeypot!\n")
        return True
    else:
        return False




def detectKippoCowrie(host, port):
    score = 0
    
    print("[+] Detecting Kippo/Cowrie technique #1 - bad version")
    sockfd = connectToSSH(host, port)
    
    if sockfd:
        if probeBadVersion(sockfd):
            score += 1
    else:
        print("Socket error in probe #1")
        sys.exit(ERROR)
        
    
    print("[+] Detecting Kippo/Cowrie technique #2 - spacer")
    sockfd = connectToSSH(host, port)
    
    if sockfd:
        if probeSpacerPacketCorrupt(sockfd):
            score += 1
    else:
        print("Socket error in probe #2")
        sys.exit(ERROR)
        
        
    print("[+] Detecting Kippo/Cowrie technique #3 - double banner")
    sockfd = connectToSSH(host, port)

    if sockfd:
        if probeDoubleBanner(sockfd):
            score += 1
    else:
        print("Socket error in probe #3")
        sys.exit(ERROR)
    
    
    return score


def main():
    if len(sys.argv) >= 1:
        host = sys.argv[1]
        port = int(sys.argv[2])
    
    score = detectKippoCowrie(host, port)
    
    print("\t\t\t[+] Detection score for %s on port %d: %d" % (host, port, score))
    
    if score >= 2:
        print("\t\t\t[*] IT'S A TRAP! %s on port %d is definitely a Kippo/Cowrie honeypot [*]" % (host, port))
    elif score == 1:
        print("\t\t\t[+] %s:%d may be a Kippo/Cowrie honeypot or a misconfigured OpenSSH" % (host, port))
    elif score == 0:
        print("\t\t\t[!] %s on port %d is not a honeypot." % (host, port))

if __name__ == '__main__':
    main()