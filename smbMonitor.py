from scapy.all import *
#ImportError: cannot import name 'NPCAP_PATH' from 'scapy.arch.pcapdnet' (C:\Users\scott\AppData\Local\Programs\Python\Python37-32\lib\site-packages\scapy\arch\pcapdnet.py)
def smbCheck(pkt):
    pkt.show() # debug statement
    print("******************************************************************")
    print(dir(pkt))
    print(type(pkt))
    print("******************************************************************")

sniff(iface="Realtek PCIe GBE Family Controller", prn=smbCheck, filter="tcp", store=0)
