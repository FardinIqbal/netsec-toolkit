from scapy.all import IP, TCP, sr1, send

TARGET = "scanme.nmap.org"
PORTS = [22, 80, 443, 9929]
TIMEOUT = 3

for port in PORTS:
    pkt = IP(dst=TARGET) / TCP(dport=port, flags="S")
    reply = sr1(pkt, timeout=TIMEOUT, verbose=0)

    if reply is None:
        print(f"Port {port}:\tfiltered")
    elif reply.haslayer(TCP):
        tcp_flags = reply[TCP].flags
        if tcp_flags == 0x12:
            print(f"Port {port}:\topen")
            rst = IP(dst=TARGET) / TCP(
                dport=port,
                sport=reply[TCP].dport,
                flags="R",
                seq=reply[TCP].ack
            )
            send(rst, verbose=0)
        elif tcp_flags == 0x14:
            print(f"Port {port}:\tclosed")
        else:
            print(f"Port {port}:\tunexpected flags: {tcp_flags:#x}")
    else:
        print(f"Port {port}:\tunexpected response")
