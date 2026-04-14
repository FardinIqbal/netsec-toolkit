from scapy.all import IP, ICMP, sr1
import time

TARGET = "scanme.nmap.org"
TTL_TARGET = "google.com"
TTL_VALUES = [1, 5, 10]

ICMP_TYPES = {0: "Echo Reply", 11: "Time Exceeded"}

print("--- Ping to scanme.nmap.org ---")
pkt = IP(dst=TARGET) / ICMP()
start = time.time()
reply = sr1(pkt, timeout=5, verbose=0)
end = time.time()

if reply is not None:
    rtt = (end - start) * 1000
    print(f"Reply from {reply.src}, RTT: {rtt:.2f} ms")
else:
    print("No reply received.")

print()
print("--- TTL Exploration to google.com ---")
for ttl in TTL_VALUES:
    pkt = IP(dst=TTL_TARGET, ttl=ttl) / ICMP()
    start = time.time()
    reply = sr1(pkt, timeout=5, verbose=0)
    end = time.time()

    if reply is not None:
        type_name = ICMP_TYPES.get(reply.type, f"Unknown ({reply.type})")
        rtt = (end - start) * 1000
        print(f"TTL={ttl}: Reply from {reply.src}, ICMP type: {reply.type} ({type_name}), RTT: {rtt:.2f} ms")
    else:
        print(f"TTL={ttl}: No reply (packet dropped)")
