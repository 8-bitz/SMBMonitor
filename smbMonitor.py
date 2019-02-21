from scapy.all import *

def smbCheck(pkt):
    pkt.show() # debug statement
    print("******************************************************************")
    print(dir(pkt))
    print(type(pkt))
    print("******************************************************************")

sniff(iface="Realtek PCIe GBE Family Controller", prn=smbCheck, filter="tcp", store=0)
