#!/usr/bin/env python
import optparse
import scapy.all as scapy


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


def process_sniffed_packets(packet):
    try:
        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc
            if real_mac != response_mac:
                print("[-] You are under attack!!!")
    except Exception as e:
        print(e)


def get_mac(ip):
    # creating a arp request
    arp_request = scapy.ARP(pdst=ip)
    # creating broadcast
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # scapy.ls(scapy.Ether())

    # combining arp request and broadcast packets
    arp_request_broadcast = broadcast/arp_request

    try:
        # send and receive arp broadcast packets
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        return answered_list[0][1].hwsrc
    except Exception:
        pass


sniff(get_arguments())
