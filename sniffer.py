from scapy.all import sniff, IP, TCP, UDP

def show(pkt):
    if IP in pkt:
        proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "OTHER"
        print(f"{pkt[IP].src} -> {pkt[IP].dst} | {proto}")

sniff(prn=show, count=10)
