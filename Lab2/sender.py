import argparse
import ipaddress
import os
import select
import signal
import socket
import struct
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Union, Dict

BUF_SIZE = 1024
HEADER_SIZE = 26
INNER_HEADER_SIZE = 9


class Header:
    def __init__(self, priority: int, src_ip: Union[int, str], src_port: int, dst_ip: Union[int, str], dst_port: int, outer_length: int,
                 packet_type: str, seq_no: int, inner_length: int):
        self.priority = priority
        assert 0 <= int(self.priority) < 128
        self.src_ip = ipaddress.ip_address(src_ip)
        self.src_port = src_port
        self.dst_ip = ipaddress.ip_address(dst_ip)
        self.dst_port = dst_port
        self.outer_length = outer_length
        self.packet_type = packet_type
        self.seq_no = seq_no
        self.inner_length = inner_length

    @classmethod
    def from_bytes(cls, header_data: bytes):
        assert len(header_data) == HEADER_SIZE
        data_tuple = struct.unpack("!cIHIHIc2I", header_data)
        return cls(int(data_tuple[0]), int(data_tuple[1]), int(data_tuple[2]), int(data_tuple[3]), int(data_tuple[4]), int(data_tuple[5]),
                   data_tuple[6].decode("utf-8"), int(data_tuple[7]), int(data_tuple[8]))

    def __str__(self):
        return (f"Header(priority={self.priority},src_ip={self.src_ip},src_port={self.src_port},dst_ip={self.dst_ip},dst_port={self.dst_port},"
                f"outer_length={self.outer_length},type={self.packet_type},seq_no={self.seq_no},length={self.inner_length})")

    def to_bytes(self):
        return struct.pack("!cIHIHIc2I", str(self.priority).encode(), int(self.src_ip), self.src_port, int(self.dst_ip), self.dst_port,
                           self.outer_length, str(self.packet_type).encode(), self.seq_no, self.inner_length)


class SenderWindow:
    @dataclass
    class PacketData:
        retransmit_count: int
        last_transmit_time: datetime
        packet: bytes

    def __init__(self, rate: float, max_window_size: int, priority: int, timeout: int, emulator_name: str, emulator_port: int, sock: socket.socket):
        self.max_window_size = max_window_size
        self.priority = priority
        self.timeout = timeout
        self.emulator_ip = socket.gethostbyname(emulator_name)
        self.emulator_port = emulator_port
        self.rate = rate
        self.seq_no = 1
        self.window: Dict[int, SenderWindow.PacketData] = dict()  # -1 means ack received or failed to sent
        self.first_transmission_count = 0
        self.retransmission_count = 0
        self.sock = sock

    def retransmit_or_print_error(self) -> bool:
        all_packet_done = True
        for seq_no in self.window:
            all_packet_done = all_packet_done & (self.window[seq_no].retransmit_count == -1)
            if self.window[seq_no].retransmit_count == -1:
                continue
            if self.window[seq_no].retransmit_count == 5:
                print("Failed to transmit", Header.from_bytes(self.window[seq_no].packet[:HEADER_SIZE]))
                self.window[seq_no].retransmit_count = -1
                continue
            if datetime.now() > self.window[seq_no].last_transmit_time + timedelta(milliseconds=self.timeout):
                self.window[seq_no].retransmit_count += 1
                time.sleep(1 / self.rate)
                print(f"Retransmitting packet: {Header.from_bytes(self.window[seq_no].packet[:HEADER_SIZE])}\n")
                self.sock.sendto(self.window[seq_no].packet, (self.emulator_ip, self.emulator_port))
                self.window[seq_no].last_transmit_time = datetime.now()
                self.retransmission_count += 1
        return all_packet_done

    def form_transmit_window(self, packet: bytes) -> bool:
        assert len(self.window) < self.max_window_size
        self.window[Header.from_bytes(packet[:HEADER_SIZE]).seq_no] = SenderWindow.PacketData(0, datetime.now(), packet)
        time.sleep(1 / self.rate)
        print(f"First time trasmission: {Header.from_bytes(packet[:HEADER_SIZE])}\n")
        self.sock.sendto(packet, (self.emulator_ip, self.emulator_port))
        self.seq_no += 1
        self.first_transmission_count += 1
        return len(self.window) < self.max_window_size

    def ack_packet(self, header: Header):
        if header.seq_no in self.window:
            self.window[header.seq_no].retransmit_count = -1

    def clear_window(self):
        self.window.clear()

    def send_end_packet(self, requester_port: int, dst_ip: str, self_port: int):
        src_ip = socket.gethostbyname(socket.gethostname())
        packet_end: bytes = Header(self.priority, src_ip, self_port, dst_ip, requester_port, INNER_HEADER_SIZE, 'E', self.seq_no, 0).to_bytes()
        time.sleep(1 / self.rate)
        self.sock.sendto(packet_end, (self.emulator_ip, self.emulator_port))

    def print_summary(self, self_addr: str, self_port: int):
        loss_rate = float(self.retransmission_count) * 100.0 / float(self.retransmission_count + self.first_transmission_count)
        print("Summary")
        print(f"sender addr:             {self_addr}:{self_port}")
        print(f"Average Loss Rate:       {loss_rate}")
        print()


def send_file(requester_port: int, self_port: int, rate: float, length: int, filename: str, request_packet_header: Header, emulator_name: str,
              emulator_port: int, priority: int, timeout: int, sock: socket):
    sender_window = SenderWindow(rate, request_packet_header.inner_length, priority, timeout, emulator_name, emulator_port, sock)
    sender_window.clear_window()

    if not os.path.exists(filename):
        sender_window.send_end_packet(requester_port, str(request_packet_header.src_ip), self_port)
        return

    def try_completing_window():
        while True:
            while True:
                read_sockets, _, _ = select.select([sock], [], [], 0)
                if sock not in read_sockets:
                    break
                header_ack: Header = Header.from_bytes(sock.recv(BUF_SIZE)[:HEADER_SIZE])
                assert header_ack.packet_type == 'A'
                sender_window.ack_packet(header_ack)
            if sender_window.retransmit_or_print_error():
                break
        sender_window.clear_window()

    with open(filename, 'rb') as f:
        src_ip = socket.gethostbyname(socket.gethostname())
        dst_ip, dst_port = request_packet_header.src_ip, requester_port
        while byte := f.read(length):
            outer_packet_length = len(byte) + INNER_HEADER_SIZE
            packet = Header(priority, src_ip, self_port, str(dst_ip), dst_port, outer_packet_length, 'D', sender_window.seq_no,
                            len(byte)).to_bytes() + byte
            if not sender_window.form_transmit_window(packet):
                try_completing_window()
        try_completing_window()
        sender_window.send_end_packet(requester_port, str(request_packet_header.src_ip), self_port)
        sender_window.print_summary(src_ip, self_port)


def receive_request(port: int, requester_port: int, rate: float, length: int, emulator_name: str, emulator_port: int, priority: int, timeout: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((socket.gethostname(), port))
    sock.setblocking(False)

    while True:
        read_sockets, _, _ = select.select([sock], [], [], 0)
        if sock in read_sockets:
            break
    packet = sock.recv(BUF_SIZE)
    header, data = Header.from_bytes(packet[:HEADER_SIZE]), packet[HEADER_SIZE:]
    assert header.packet_type == 'R'
    send_file(requester_port, port, rate, length, data.decode("utf-8"), header, emulator_name, emulator_port, priority, timeout, sock)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='File Sender')
    parser.add_argument('-p', '--port', type=int, help='port on which the sender waits for requests', required=True)
    parser.add_argument('-g', '--requester_port', type=int, help='port on which the requester is waiting', required=True)
    parser.add_argument('-r', '--rate', type=float, help='number of packets to be sent per second', required=True)
    parser.add_argument('-q', '--seq_no', type=int, help='initial sequence of the packet exchange', required=True)
    parser.add_argument('-l', '--length', type=int, help='length of the payload (in bytes) in the packets', required=True)
    parser.add_argument('-f', '--f_hostname', type=str, help='the host name of the emulator', required=True)
    parser.add_argument('-e', '--f_port', type=int, help='the port of the emulator', required=True)
    parser.add_argument('-i', '--priority', type=int, help='the priority of the sent packets', required=True)
    parser.add_argument('-t', '--timeout', type=int, help='the timeout for retransmission for lost packets in the unit of milliseconds',
                        required=True)

    args = parser.parse_args()
    signal.signal(signal.SIGINT, lambda x, y: sys.exit(1))
    receive_request(args.port, args.requester_port, args.rate, args.length, args.f_hostname, args.f_port, args.priority, args.timeout)
