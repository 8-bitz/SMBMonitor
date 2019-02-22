from scapy.all import *
import os
import socket

interface = "Intel(R) Ethernet Connection I217-LM"
infList = get_windows_if_list()
interface = infList[0].get("name")

localIP = socket.gethostbyname(socket.gethostname())

smb23 = "xfesmb"
smb1 = "xffsmb"

connectionSet = set()



def smbCheck(pkt):
	#pkt.show() # debug statement
	global interface
	global localIP
	if TCP in pkt:
		#if str(pkt[IP].dst) == "10.8.4.53":
		outstring = ""
		#print("******************************************************************")
		#print(dir(pkt))
		#print(pkt.show())
		#try:			
		#print(pkt[IP].dst)
		#print(pkt[IP].proto)
		#print("HEXY TIME")		
		
		pktPayload = str(pkt[TCP].payload).lower().split("\\")
		if len(pktPayload)> 4:				
			if smb23 in pktPayload[4]:
				#*********************************************************************	
				srcName = "<unknown>"
				try:
					srcName = str(socket.gethostbyaddr(pkt[IP].src)[0])
				except:
					pass
				dstName = "<unknown>"
				try:
					dstName = str(socket.gethostbyaddr(pkt[IP].dst)[0])
				except:
					pass
				#*********************************************************************	
				if pkt[IP].src == localIP:
					outstring = "SMB 2/3 --> " + pkt[IP].src + " (" + srcName + ") --> " + pkt[IP].dst + " (" + dstName + ")"					
				else:
					outstring = "SMB 2/3 --> " + pkt[IP].dst + " (" + dstName + ") <-- " + pkt[IP].src + " (" + srcName  + ")"
					#outstring = pkt[IP].src + " (" + srcName + ") --> " + pkt[IP].dst + " (" + dstName + ") : SMB 2/3"
				
				connectionSet.add(outstring)
				os.system("cls")
				print(interface)
				print(localIP)
				print("SMB Ver. --> Source (HostName) --> Destination (Host Name)")
				for i in sorted(connectionSet):
					print(i)
				#print(outstring)
				
			elif smb1 in pktPayload[4]:
				#*********************************************************************	
				srcName = "<unknown>"
				try:
					srcName = str(socket.gethostbyaddr(pkt[IP].src)[0])
				except:
					pass
				dstName = "<unknown>"
				try:
					dstName = str(socket.gethostbyaddr(pkt[IP].dst)[0])
				except:
					pass
				#*********************************************************************					
				if pkt[IP].src == localIP:
					outstring = "SMB 1 --> " + pkt[IP].src + " (" + srcName + ") --> " + pkt[IP].dst + " (" + dstName + ")"
				else:
					outstring = "SMB 1 --> " + pkt[IP].dst + " (" + dstName + ") <-- " + pkt[IP].src + " (" + srcName  + ")"
				connectionSet.add(outstring)
				#print(outstring)
				os.system("cls")
				print(interface)
				print(localIP)
				print("Source --> Destination : SMB Ver.")
				for i in connectionSet:
					print(i)
			else:
				pass
			#print("******************************************************************")
			#input("pause")
		
infList = get_windows_if_list()
interface = infList[0].get("name")		
print(interface)
print(localIP)
sniff(iface=interface, prn=smbCheck, filter="tcp", store=0)
