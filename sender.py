import argparse
import socket
import struct
import time
import os
from datetime import datetime

BUF_SIZE = 1024


class Header:
    def __init__(self, packet_type: bytes, seq_no, length):
        self.type = packet_type.decode("utf-8")
        self.seq_no = socket.ntohl(seq_no)
        self.length = socket.ntohl(length)

    def __str__(self):
        return f"Header=(type={self.type},seq_no={self.seq_no},length={self.length}"


def print_packet(packet_type: str, requester_addr: str, request_from_port: int, seq_num: int, payload: bytes):
    if packet_type == 'D':
        print("DATA Packet")
    if packet_type == 'E':
        print("END Packet")
    print(f"send time:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}")
    print(f"requester addr:  {requester_addr}:{request_from_port}")
    print(f"Sequence num:    {seq_num}")
    print(f"length:          {len(payload)}")
    print(f"payload:         {payload[:4].decode('utf-8')}")
    print()


def send_file(requester_port: int, rate: float, seq_no: int, length: int, filename: str, requester_address: str, request_from_port: int,
              sock: socket):
    seq_curr = seq_no

    def send_end_packet():
        packet_end = struct.pack("!c2I", b'E', socket.htonl(seq_curr), 0)
        time.sleep(1 / rate)
        sock.sendto(packet_end, (requester_address, requester_port))
        print_packet('E', requester_address, request_from_port, seq_curr, b'')

    if not os.path.exists(filename):
        send_end_packet()
        return

    with open(filename, 'rb') as f:
        while byte := f.read(length):
            packet = struct.pack("!c2I", b'D', socket.htonl(seq_curr), socket.htonl(len(byte))) + byte
            time.sleep(1 / rate)
            sock.sendto(packet, (requester_address, requester_port))
            print_packet('D', requester_address, request_from_port, seq_curr, byte)
            seq_curr += len(byte)
        send_end_packet()


def receive_request(port: int, requester_port: int, rate: int, seq_no: int, length: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', port))

    packet, from_address = sock.recvfrom(BUF_SIZE)
    header, data = Header(*struct.unpack("!c2I", packet[:9])), packet[9:]
    assert header.type == 'R'
    send_file(requester_port, rate, seq_no, length, data.decode("utf-8"), from_address[0], int(from_address[1]), sock)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='File Sender')
    parser.add_argument('-p', '--port', type=int, help='port on which the sender waits for requests', required=True)
    parser.add_argument('-g', '--requester_port', type=int, help='port on which the requester is waiting', required=True)
    parser.add_argument('-r', '--rate', type=float, help='number of packets to be sent per second', required=True)
    parser.add_argument('-q', '--seq_no', type=int, help='initial sequence of the packet exchange', required=True)
    parser.add_argument('-l', '--length', type=int, help='length of the payload (in bytes) in the packets', required=True)

    args = parser.parse_args()
    receive_request(args.port, args.requester_port, args.rate, args.seq_no, args.length)
