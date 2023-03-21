import argparse
import ipaddress
import logging
import random
import select
import signal
import socket
import struct
import sys
from collections import deque, defaultdict
from datetime import datetime, timedelta
from typing import Dict, Tuple, Union

BUF_SIZE = 1024
HEADER_SIZE = 18


class Header:
    def __init__(self, priority: int, src_ip: Union[int, str], src_port: int, dst_ip: Union[int, str], dst_port: int, outer_length: int,
                 packet_type: str):
        self.priority = priority
        assert 0 <= int(self.priority) < 128
        self.src_ip = ipaddress.ip_address(src_ip)
        self.src_port = src_port
        self.dst_ip = ipaddress.ip_address(dst_ip)
        self.dst_port = dst_port
        self.outer_length = outer_length
        self.packet_type = packet_type

    @classmethod
    def from_bytes(cls, header_data: bytes):
        assert len(header_data) == HEADER_SIZE
        data_tuple = struct.unpack("!cIHIHIc", header_data)
        return cls(int(data_tuple[0]), int(data_tuple[1]), int(data_tuple[2]), int(data_tuple[3]), int(data_tuple[4]), int(data_tuple[5]),
                   data_tuple[6].decode("utf-8"))

    def to_bytes(self):
        assert self.src_ip != 0
        return struct.pack("!cIHIHIc", str(self.priority).encode(), int(self.src_ip), self.src_port, int(self.dst_ip), self.dst_port,
                           self.outer_length, str(self.packet_type).encode())

    def __str__(self):
        return (f"Header(priority={self.priority},src_ip={self.src_ip},src_port={self.src_port},dst_ip={self.dst_ip},dst_port={self.dst_port},"
                f"outer_length={self.outer_length},packet_type={self.packet_type})")


class HopDetails:
    def __init__(self, next_hop_ip: Union[int, str], next_hop_port: int, delay: int, loss_probability: int, queue_size: int):
        self.next_hop_ip = ipaddress.ip_address(next_hop_ip)
        self.next_hop_port = next_hop_port
        self.delay = delay
        self.loss_probability = loss_probability
        self.queue_with_priority = defaultdict(lambda: deque())
        self.delay_packet: Union[Tuple[datetime, bytes], None] = None
        self.queue_size = queue_size

    def __str__(self):
        return f"HopDetails(next-hop-ip={self.next_hop_ip},next-hop-port={self.next_hop_port},delay={self.delay},loss_prob={self.loss_probability})"

    def print_receive_queue(self):
        for priority in self.queue_with_priority:
            print("Priority:", priority)
            for packet in self.queue_with_priority[priority]:
                print(Header.from_bytes(packet[:HEADER_SIZE]))
            print()

    def print_delay_packet(self):
        print(self.delay_packet[0], Header.from_bytes(self.delay_packet[1][:HEADER_SIZE]))

    def push_queue(self, packet: bytes):
        header = Header.from_bytes(packet[:HEADER_SIZE])
        print("Packet pushed", datetime.now(), header, packet[HEADER_SIZE + 8:])
        if len(self.queue_with_priority[header.priority]) >= self.queue_size:
            print("Queue full drop packet", header)
            return
        self.queue_with_priority[header.priority].append(packet)

    def send_packets_if_ready(self, sock: socket.socket):
        if self.delay_packet is not None:
            if datetime.now() <= self.delay_packet[0] + timedelta(milliseconds=self.delay):
                return
            if random.randint(1, 100) <= self.loss_probability and Header.from_bytes(self.delay_packet[1][:HEADER_SIZE]).packet_type != 'E':
                print("Dropping packet", datetime.now(), Header.from_bytes(self.delay_packet[1][:HEADER_SIZE]),
                      self.delay_packet[1][HEADER_SIZE + 8:])
                self.delay_packet = None
                return
            print("Sending packet", datetime.now(), Header.from_bytes(self.delay_packet[1][:HEADER_SIZE]), self.delay_packet[1][HEADER_SIZE + 8:])
            sock.sendto(self.delay_packet[1], (str(self.next_hop_ip), self.next_hop_port))
            self.delay_packet = None
        else:
            for priority in sorted(self.queue_with_priority.keys()):
                if len(self.queue_with_priority[priority]) > 0:
                    self.delay_packet = (datetime.now(), self.queue_with_priority[priority].popleft())
                    print("Delaying packet", self.delay_packet[0], Header.from_bytes(self.delay_packet[1][:HEADER_SIZE]),
                          self.delay_packet[1][HEADER_SIZE + 8:])
                    break


ROUTING_TABLE: Dict[Tuple[ipaddress.IPv4Address, int], HopDetails] = dict()


def read_routing_table(table_file: str, port: int, queue_size: int):
    self_ip = socket.gethostbyname(socket.gethostname())
    with open(table_file, 'r') as f_in:
        for line in f_in.readlines():
            if line.startswith('#'):
                continue
            tokens = str(line).strip("\n ").split(" ")
            if tokens[0] != self_ip and tokens[0] != socket.gethostname():
                continue
            if int(tokens[1]) != int(port):
                continue
            dst_ip = ipaddress.ip_address(socket.gethostbyname(tokens[2]))
            next_hop_ip = ipaddress.ip_address(socket.gethostbyname(tokens[4]))
            ROUTING_TABLE[(dst_ip, int(tokens[3]))] = HopDetails(str(next_hop_ip), int(tokens[5]), int(tokens[6]), int(tokens[7]), queue_size)


def find_next_hop(header: Header) -> Union[HopDetails, None]:
    if (header.dst_ip, header.dst_port) not in ROUTING_TABLE:
        return None
    return ROUTING_TABLE[(header.dst_ip, header.dst_port)]


def perform_routing(port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', port))
    sock.setblocking(False)

    while True:
        while True:
            read_sockets, _, _ = select.select([sock], [], [], 0)
            if sock in read_sockets:
                packet = sock.recv(BUF_SIZE)
                next_hop = find_next_hop(Header.from_bytes(packet[:HEADER_SIZE]))
                if next_hop is not None:
                    next_hop.push_queue(packet)
            else:
                break
        for next_hop in list(ROUTING_TABLE.values()):
            next_hop.send_packets_if_ready(sock)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='Emulator')
    parser.add_argument('-p', '--port', type=int, help='the port of the emulator', required=True)
    parser.add_argument('-q', '--queue_size', type=int, help='the size of each of the three queues', required=True)
    parser.add_argument('-f', '--filename', type=str, help='the name of the file containing the static forwarding table', required=True)
    parser.add_argument('-l', '--log', type=str, help='the name of the log file', required=True)

    args = parser.parse_args()
    logging.basicConfig(filename=args.log)
    signal.signal(signal.SIGINT, lambda x, y: sys.exit(1))
    read_routing_table(args.filename, args.port, args.queue_size)
    perform_routing(int(args.port))
