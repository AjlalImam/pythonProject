#!/usr/bin/env python
import subprocess
import optparse
import re


# function that takes arguments
def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Enter Interface to change its MAC")
    parser.add_option("-m", "--mac", dest="mac", help="Enter new MAC address")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please Enter Interface, use --help for more info")
    elif not options.mac:
        parser.error("[-] Please Enter new MAC, use --help for more info")
    return options.interface, options.mac


# function that changes mac address
def change_mac(inter, mac, omac):
    print("[+] Changing MAC for "+inter+" from"+omac+" to "+mac)
    subprocess.call(["ifconfig", inter, "down"])
    subprocess.call(["ifconfig", inter, "hw", "ether", mac])
    subprocess.call(["ifconfig", inter, "up"])


# reading current mac address
def read_current_mac(interface):
    read_ifconfig = subprocess.check_output(["ifconfig", interface])
    old_mac = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(read_ifconfig))
    if old_mac:
        return old_mac.group(0)
    else:
        print("[-] Could not read MAC address")


# calling the two functions
interface, new_mac = get_arguments()
old_mac = read_current_mac(interface)
print("[+] Current MAC = "+str(old_mac))
change_mac(interface, new_mac, old_mac)
current_mac = read_current_mac(interface)
if current_mac == new_mac:
    print("[+] MAC successfully changed ")
else:
    print("[-] MAC not changed ")
