from scapy.all import *
import pickle
import re

destinations = pickle.load(open('ipOlicyber', 'rb'))
# set of ip of the challenges

rgx_flags = '(flag|ptm)\{[0-9a-zA-Z_!?-]+\}'

def packetGood(pkt):
    if not pkt.haslayer(IP):
        return False
    if not pkt.haslayer(TCP):
        return False
    if not pkt[TCP].payload:
        return False
    if not pkt.haslayer(Raw):
        return False
    return True

def callback(pkt):
    ip_src=pkt[IP].src
    ip_dst=pkt[IP].dst
    if ip_src in destinations or ip_dst in destinations:
        if packetGood(pkt):
            payload = pkt[Raw].load
            flags = re.search(rgx_flags, payload.decode())
            if flags:
                print(flags.group(0))


# C:\Windows\System32\Npcap\WlanHelper.exe "Wi-Fi 2" mode managed || monitor
# o uso acrylic


capture = sniff(filter="tcp", prn=lambda x: callback(x), store=0, ifaces='Wi-Fi')

