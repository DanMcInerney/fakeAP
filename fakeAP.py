#!/usr/bin/env python

import os
from subprocess import Popen, PIPE
DN = open(os.devnull, 'w')
import time
import sys
import re
import signal
import argparse

ipf = 0

def parse_args():
    #Create the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--channel", help="Choose the channel for the fake AP. Default is channel 6.")
    parser.add_argument("-e", "--essid", help="Choose the ESSID for the fake AP. Default is 'Free Wifi'. Wrap in quotes if it is more than 1 word: -e 'Free Wifi'")
    return parser.parse_args()

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
        sys.exit('['+R+'-'+W+'] You need at least 2 wireless interfaces. Please bring 2 up and retry.')
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
    print '[*] Setting up iptables'
    os.system('iptables -X')
    os.system('iptables -F')
    os.system('iptables -t nat -F')
    os.system('iptables -t nat -X')
    os.system('iptables -t nat -A POSTROUTING -o %s -j MASQUERADE' % inet_iface)
    with open('/proc/sys/net/ipv4/ip_forward', 'r+') as ipf:
        ipf.write('1\n')
        print '[*] Enabled IP forwarding'
        return ipf.read()

def start_monitor(ap_iface, args):
    print '[*] Setting up monitor mode'
    channel = '6'
    if args.channel:
        channel = args.channel
    proc = Popen(['airmon-ng', 'start', ap_iface, channel], stdout=PIPE, stderr=DN)
    for line in proc.communicate()[0].split('\n'):
        if "monitor mode enabled" in line:
            line = line.split()
            mon_mode = line[4][:-1]
            return mon_mode

def start_ap(mon_mode, args):
    channel = '6'
    essid = 'Free Wifi'
    if args.channel:
        channel = args.channel
    if args.essid:
        essid = args.essid
    Popen(['airbase-ng', '-c', channel, '-e', essid, '-v', mon_mode], stdout=DN, stderr=DN)
    time.sleep(6) # Copied from Pwnstar which said it was necessary?
    Popen(['ifconfig', 'at0', 'up', '10.0.0.1', 'netmask', '255.255.255.0'], stdout=DN, stderr=DN)
    Popen(['ifconfig', 'at0', 'mtu', '1400'], stdout=DN, stderr=DN)

def dhcp_conf(ipprefix):
    config = 'default-lease-time 300;\n\
            max-lease-time 360;\n\
            ddns-update-style none;\n\
            authoritative;\n\
            log-facility local7;\n\
            subnet %s netmask 255.255.255.0 {\n\
            range %s;\n\
            option routers %s;\n\
            option domain-name-servers %s;\n\
            }'
    if ipprefix == '19' or ipprefix == '17':
        with open('/tmp/dhcpd.conf', 'w') as dhcpconf:
            # subnet, range, router, dns
            dhcpconf.write(config % ('10.0.0.0', '10.0.0.2 10.0.0.100', '10.0.0.1', '8.8.8.8'))
    elif iprefix == '10':
        with open('/tmp/dhcpd.conf', 'w') as dhcpconf:
            dhcpconf.write(config % ('172.16.0.0', '172.16.0.2 172.16.0.100', '172.16.0.1', '8.8.8.8'))
    return '/tmp/dhcpd.conf'

def dhcp(dhcpconf, ipprefix):
    print '[*] Clearing leases and starting DHCP'
    os.system('echo > /var/lib/dhcp/dhcpd.leases')
    os.system('dhcpd -cf %s' % dhcpconf)
    if ipprefix == '19' or ipprefix == '17':
        os.system('route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1')
    elif ipprefix == '10':
        os.system('route add -net 172.16.0.0 netmask 255.255.255.0 gw 172.16.0.1')

def cleanup(signal, frame):
    print 'learing iptables and turning off IP forwarding...'
    with open('/proc/sys/net/ipv4/ip_forward', 'r+') as forward:
        forward.write(ipf)
    os.system('iptables -F')
    os.system('iptables -X')
    os.system('iptables -t nat -F')
    os.system('iptables -t nat -X')
    os.system('pkill airbase-ng')
    os.system('pkill dhcpd')
    sys.exit(0)

def main(args):
    global ipf
    monitors, interfaces = iwconfig()
    rm_mon(monitors)
    inet_iface, ipprefix = internet_info(interfaces)
    ap_iface = AP_iface(interfaces, inet_iface)
    ipf = iptables(inet_iface)
    mon_mode = start_monitor(ap_iface, args)
    start_ap(mon_mode, args)
    dhcpconf = dhcp_conf(ipprefix)
    dhcp(dhcpconf, ipprefix)
    signal.signal(signal.SIGINT, cleanup)
    while 1:
        time.sleep(10)
#        try:
#            time.sleep(5)
#        except KeyboardInterrupt:
#            os.system('airmon-ng stop mon0')
#            os.system('ifconfig at0 down')
#            os.system('ps faux | grep -i airbase')
#            sys.exit()

main(parse_args())
