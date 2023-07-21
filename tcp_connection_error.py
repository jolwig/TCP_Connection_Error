# if host sends packet with SYN flag and does not recieve packet with SYN flag, raise an error #

from scapy.all import sniff, TCP

src_dst = {}

def packet_callback(packet):

    if TCP in packet and packet[TCP].flags & 2:

        #add source ip:port (key) and destination ip:port (value) to src_dst dictionary
        src_ip_p = packet.sprintf('{IP:%IP.src%}:{TCP:%TCP.sport%}')
        dst_ip_p = packet.sprintf('{IP:%IP.dst%}:{TCP:%TCP.dport%}')
        src_dst[src_ip_p] = dst_ip_p
        print(f"{src_ip_p} --> {dst_ip_p}")
    
sniff(prn=packet_callback, timeout=10)

#If src ip:port not in dst ip:port, raise an error

for key, value in src_dst.items():
    if key not in src_dst.values():
        print(f"TCP Connection Error")
        print(f"Source IP:Port is {key}")
        print(f"Destination IP:Port is {value}")