from scapy.all import sniff, ARP, DNS, IP
from collections import Counter
import time

packet_counter = Counter()

def process_packet(packet):
    if ARP in packet and packet[ARP].op == 1:
        print(f"[ARP] طلب ARP من {packet[ARP].psrc} يبحث عن {packet[ARP].pdst}")
        packet_counter["ARP"] += 1

    elif packet.haslayer(DNS):
        query = packet[DNS].qd.qname.decode() if packet[DNS].qd else "?"
        print(f"[DNS] {packet[IP].src} → {query}")
        packet_counter["DNS"] += 1

    elif packet.haslayer(IP):
        proto = packet[IP].proto
        print(f"[IP] {packet[IP].src} → {packet[IP].dst} | بروتوكول: {proto}")
        packet_counter["IP"] += 1

def print_summary():
    print("\n[📊 ملخص التحليل]")
    for proto, count in packet_counter.items():
        print(f"{proto} : {count} حزمة")

def main():
    print("[*] بدء تحليل الشبكة... اضغط Ctrl+C للإيقاف.")
    try:
        sniff(prn=process_packet, store=0)
    except KeyboardInterrupt:
        print_summary()

if __name__ == "__main__":
    main()
