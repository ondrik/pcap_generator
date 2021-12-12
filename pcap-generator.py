#!/usr/bin/env python3
import argparse
import math
from scapy.all import IP, UDP, TCP, Raw, wrpcap

DPORT = 80
SPORT = 2222
MAX_RAWDATA_SIZE =  9000 # 1500

NO_FLAG  = 0x00
FIN_FLAG = 0x01
SYN_FLAG = 0x02
ACK_FLAG = 0x10
SYN_ACK_FLAG = SYN_FLAG + ACK_FLAG
FIN_ACK_FLAG = FIN_FLAG + ACK_FLAG

SRC_IP = "100.0.0.1"
DST_IP = "172.16.0.1"

def createPcapFile(data, outfile, repeat=1):
    pkts = []

    ip_send = IP(src=SRC_IP, dst=DST_IP)
    ip_recv = IP(src=DST_IP, dst=SRC_IP)

    # three-way handshake
    pkts += ip_send / TCP(sport=SPORT, dport=DPORT, flags=SYN_FLAG, seq=0, ack=0)
    pkts += ip_recv / TCP(sport=DPORT, dport=SPORT, flags=SYN_ACK_FLAG, seq=0, ack=1)
    pkts += ip_send / TCP(sport=SPORT, dport=DPORT, flags=ACK_FLAG, seq=1, ack=1)

    seq = 1
    for i in range(0,repeat):
        data_index = 0
        # do TCP segmentation for packets larger than MAX_RAWDATA_SIZE
        while data_index < len(data):
            tcp = TCP(sport=SPORT, dport=DPORT, flags=ACK_FLAG, seq=seq, ack=1)
            data_end = min(data_index + MAX_RAWDATA_SIZE, len(data))
            payload = data[data_index : data_end]
            # print(f"data start = {data_index}, data end = {data_end}")
            app = Raw(payload)
            pkt = ip_send / tcp / app
            pkts += pkt
            offset = data_end - data_index
            seq += offset
            data_index += offset

    # bulk ACK from receiver
    pkts += ip_recv / TCP(sport=DPORT, dport=SPORT, flags=ACK_FLAG, seq=1, ack=seq)

    # tear down send -> recv
    pkts += ip_send / TCP(sport=SPORT, dport=DPORT, flags=FIN_ACK_FLAG, seq=seq, ack=1)
    pkts += ip_recv / TCP(sport=DPORT, dport=SPORT, flags=ACK_FLAG, seq=1, ack=seq+1)

    # tear down recv -> send
    pkts += ip_recv / TCP(sport=DPORT, dport=SPORT, flags=FIN_ACK_FLAG, seq=1, ack=seq+1)
    pkts += ip_send / TCP(sport=SPORT, dport=DPORT, flags=ACK_FLAG, seq=seq+1, ack=2)

    wrpcap(outfile, pkts)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='PCAP generator for ReDoS strings')
    parser.add_argument('input', metavar='<input.txt>')
    parser.add_argument('output', metavar='<output.pcap>')
    parser.add_argument('-r', '--repeat', type=int, metavar='N', default=1,
        help='repeat input N times (default: %(default)s)')
    args = parser.parse_args()

    with open(args.input, "rb") as fd:
        data = fd.read()
        print(f'length = {len(data)}')
        createPcapFile(data, args.output, repeat=args.repeat)

    pass
