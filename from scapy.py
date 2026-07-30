from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def packet_callback(packet):
    if IP in packet:
        print("\n===== Packet Captured =====")
        print("Source IP      :", packet[IP].src)
        print("Destination IP :", packet[IP].dst)

        if TCP in packet:
            print("Protocol       : TCP")
        elif UDP in packet:
            print("Protocol       : UDP")
        elif ICMP in packet:
            print("Protocol       : ICMP")
        else:
            print("Protocol       : Other")

        if packet.haslayer(Raw):
            try:
                print("Payload        :", packet[Raw].load.decode(errors="ignore"))
            except Exception:
                print("Payload        : Unable to decode")
        else:
            print("Payload        : No Data")

print("Starting Network Sniffer...")
sniff(prn=packet_callback, store=False)