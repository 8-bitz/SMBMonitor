from scapy.all import *
#ImportError: cannot import name 'NPCAP_PATH' from 'scapy.arch.pcapdnet' (C:\Users\scott\AppData\Local\Programs\Python\Python37-32\lib\site-packages\scapy\arch\pcapdnet.py)
def smbCheck(pkt):
    #pkt.show() # debug statement
    if str(pkt[IP].dst) == "10.1.1.35":
        print("******************************************************************")
        #print(dir(pkt))
        print(pkt.show())
        print(pkt[IP].dst)
        print(pkt[IP].proto)

        #print(type(pkt))
        print("******************************************************************")

sniff(iface="Realtek PCIe GBE Family Controller", prn=smbCheck, filter="tcp", store=0)
