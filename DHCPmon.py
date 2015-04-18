from scapy.all import *
import os

clients = []

def PacketHandler(pkt):
    
    if pkt.haslayer(DHCP):
        if pkt[BOOTP].yiaddr > '1':
            if pkt[BOOTP].yiaddr not in clients:
                clients.append(pkt[BOOTP].yiaddr)
                print "[+] Domain:", pkt[DHCP].options[7][1]
                print "[+] New client found:", pkt[BOOTP].yiaddr
                print
        Hostnames =  pkt[DHCP].options[2]
        if "hostname" in Hostnames:
            print "[+] Hostname: " , pkt[DHCP].options[2][1]
            del clients[:]
        
sniff(iface='wlan0', filter="udp port 68 and port 67", prn=PacketHandler)
