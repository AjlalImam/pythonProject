#!/usr/bin/env python
import scapy.all as scapy
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-r", "--range", dest="ip_range", help="Enter range or ip you want to search")
    (options, arguments) = parser.parse_args()
    if not options.ip_range:
        parser.error("[-] Please enter range or ip, use --help for more info")
    return options.ip_range

def scan(ip):
    # creating a arp request
    arp_request = scapy.ARP(pdst=ip)
    # creating broadcast
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # scapy.ls(scapy.Ether())

    # combining arp request and broadcast packets
    arp_request_broadcast = broadcast/arp_request

    # print(arp_request.summary())
    # print(broadcast.summary())
    # print(arp_request_broadcast.summary())

    # send and receive arp broadcast packets
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # Create TCP packet for OS fingerprinting
    # ip_packet = scapy.IP(dst=ip)
    # tcp_packet = scapy.TCP(dport=80, flags='S')
    # response = scapy.sr1(ip_packet / tcp_packet, timeout=1, verbose=False)

    # create ICMP packets to detect os
    icmp_request = scapy.ICMP()
    icmp_response = scapy.sr1(scapy.IP(dst=ip) / icmp_request, timeout=1, verbose=False)

    List_of_IP_MAC_OS = []
    for element in answered_list:
        os_info = "Unknown"

        # if TCp is used:
    #     if response:
    #         if response.haslayer(scapy.TCP):
    #             if response[scapy.TCP].flags == 0x12:
    #                 os_info = "Linux/Unix"
    #             elif response[scapy.TCP].flags == 0x14:
    #                 os_info = "Windows"
    #   os_info = "Unknown"

        # if ICMP is used:
        if icmp_response:
            if icmp_response.type == 0 and icmp_response.code == 0:
                os_info = "Linux/Unix"
            elif icmp_response.type == 8 and icmp_response.code == 0:
                os_info = "Windows"

        dict_of_IP_MAC_OS = {"ip": element[1].psrc, "mac": element[1].hwsrc, "OS": os_info}
        List_of_IP_MAC_OS.append(dict_of_IP_MAC_OS)
    return List_of_IP_MAC_OS


def print_result(IP_MAC_OS):
    # displaying result
    print("IP\t\t\tMAC ADDRESS\t\t\tOS "
          "INFORMATION\n------------------------------------------------------------------------------------")
    for i in range(len(IP_MAC_OS)):
        print(IP_MAC_OS[i]["ip"]+'\t\t'+IP_MAC_OS[i]["mac"]+'\t\t'+IP_MAC_OS[i]["OS"])
        print("-------------------------------------------------------------------------------------")


ip = get_arguments()
IP_MAC_OS = scan(ip)
print_result(IP_MAC_OS)