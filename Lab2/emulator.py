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
INNER_HEADER_SIZE = 9


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
    def __init__(self, next_hop_ip: Union[int, str], next_hop_port: int, delay: int, loss_probability: int):
        self.next_hop_ip = ipaddress.ip_address(next_hop_ip)
        self.next_hop_port = next_hop_port
        self.delay = delay
        self.loss_probability = loss_probability

    def __str__(self):
        return f"HopDetails(next-hop-ip={self.next_hop_ip},next-hop-port={self.next_hop_port},delay={self.delay},loss_prob={self.loss_probability})"


def find_next_hop(header: Header) -> Union[HopDetails, None]:
    if (header.dst_ip, header.dst_port) not in ROUTING_TABLE:
        return None
    return ROUTING_TABLE[(header.dst_ip, header.dst_port)]


class QueueWithPriority:
    def __init__(self, queue_size: int, sock: socket.socket):
        self.queue_size = queue_size
        self.queue_with_priority = defaultdict(lambda: deque())
        self.delay_packet: Union[Tuple[datetime, bytes], None] = None
        self.sock = sock

    def push_queue(self, packet: bytes):
        header = Header.from_bytes(packet[:HEADER_SIZE])
        next_hop = find_next_hop(header)
        if next_hop is None:
            log_loss_event("no forwarding entry found", header)
            return
        if header.packet_type == 'E':
            self.sock.sendto(packet, (str(next_hop.next_hop_ip), next_hop.next_hop_port))
            return
        if len(self.queue_with_priority[header.priority]) >= self.queue_size:
            log_loss_event(f"priority queue {header.priority} was full", header)
            return
        self.queue_with_priority[header.priority].append(packet)

    def send_packets_if_ready(self):
        if self.delay_packet is not None:
            delay_packet_header = Header.from_bytes(self.delay_packet[1][:HEADER_SIZE])
            next_hop = find_next_hop(delay_packet_header)
            if datetime.now() <= self.delay_packet[0] + timedelta(milliseconds=next_hop.delay):
                return
            if random.randint(1, 100) <= next_hop.loss_probability and delay_packet_header.packet_type != 'E':
                log_loss_event("loss event occurred", delay_packet_header)
                self.delay_packet = None
                return
            print(f"Sending packet: {delay_packet_header}\n")
            self.sock.sendto(self.delay_packet[1], (str(next_hop.next_hop_ip), next_hop.next_hop_port))
            self.delay_packet = None
        else:
            for priority in sorted(self.queue_with_priority.keys()):
                if len(self.queue_with_priority[priority]) > 0:
                    self.delay_packet = (datetime.now(), self.queue_with_priority[priority].popleft())
                    # print("Delaying packet", self.delay_packet[0], Header.from_bytes(self.delay_packet[1][:HEADER_SIZE]),
                    #       self.delay_packet[1][HEADER_SIZE + 8:])
                    break


def log_loss_event(reason: str, header: Header):
    logging.info("Packet Loss Occurred")
    logging.info("Reason: %s", reason)
    logging.info("Source: %s:%s", socket.gethostbyaddr(str(header.src_ip))[0], header.src_port)
    logging.info("Destination: %s:%s", socket.gethostbyaddr(str(header.dst_ip))[0], header.dst_port)
    logging.info("Time of Loss: %s", datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3])
    logging.info("Priority: %d", header.priority)
    logging.info("Payload size: %d\n", header.outer_length - INNER_HEADER_SIZE)


ROUTING_TABLE: Dict[Tuple[ipaddress.IPv4Address, int], HopDetails] = dict()


def read_routing_table(table_file: str, port: int):
    self_ip = socket.gethostbyname(socket.gethostname())
    with open(table_file, 'r') as f_in:
        for line in f_in.readlines():
            if line.startswith('#'):
                continue
            tokens = str(line).strip("\n ").split(" ")
            if tokens[0] != self_ip and tokens[0] != socket.gethostname() and socket.gethostbyname(tokens[0]) != self_ip:
                continue
            if int(tokens[1]) != int(port):
                continue
            dst_ip = ipaddress.ip_address(socket.gethostbyname(tokens[2]))
            next_hop_ip = ipaddress.ip_address(socket.gethostbyname(tokens[4]))
            ROUTING_TABLE[(dst_ip, int(tokens[3]))] = HopDetails(str(next_hop_ip), int(tokens[5]), int(tokens[6]), int(tokens[7]))


def perform_routing(port: int, queue_size: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', port))
    sock.setblocking(False)
    queue = QueueWithPriority(queue_size, sock)

    while True:
        while True:
            read_sockets, _, _ = select.select([sock], [], [], 0)
            if sock in read_sockets:
                packet = sock.recv(BUF_SIZE)
                queue.push_queue(packet)
            else:
                break
        queue.send_packets_if_ready()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='Emulator')
    parser.add_argument('-p', '--port', type=int, help='the port of the emulator', required=True)
    parser.add_argument('-q', '--queue_size', type=int, help='the size of each of the three queues', required=True)
    parser.add_argument('-f', '--filename', type=str, help='the name of the file containing the static forwarding table', required=True)
    parser.add_argument('-l', '--log', type=str, help='the name of the log file', required=True)

    args = parser.parse_args()
    logging.basicConfig(filename=args.log, level=logging.INFO, format='%(message)s')
    signal.signal(signal.SIGINT, lambda x, y: sys.exit(1))
    read_routing_table(args.filename, args.port)
    perform_routing(int(args.port), args.queue_size)
