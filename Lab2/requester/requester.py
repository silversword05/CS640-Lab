import argparse
import ipaddress
import select
import signal
import socket
import struct
import sys
from collections import defaultdict
from typing import Union, BinaryIO, Tuple, Dict, List

TRACKER_FILE = 'tracker.txt'
TRACKER_TABLE = defaultdict(lambda: defaultdict(tuple))
BUF_SIZE = 1024 * 5
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


class SenderDataExchange:
    def __init__(self, f_out: BinaryIO, self_port: int, emulator_name: str, emulator_port: int, file_id: int, sock: socket.socket):
        self.packet_chunks: defaultdict[int, bytes] = defaultdict(lambda: bytes())
        self.f_out = f_out
        self.self_port = self_port
        self.end_seq_no = -1
        self.file_id = file_id
        self.emulator_ip = socket.gethostbyname(emulator_name)
        self.emulator_port = emulator_port
        self.sock = sock

    def __lt__(self, other):
        return self.file_id < other.file_id

    def register_packet(self, packet: bytes) -> bool:
        header, data = Header.from_bytes(packet[:HEADER_SIZE]), packet[HEADER_SIZE:]
        if header.packet_type == 'D':
            if header.seq_no not in self.packet_chunks:
                self.packet_chunks[header.seq_no] = data
            src_ip = socket.gethostbyname(socket.gethostname())
            packet_ack = Header(1, src_ip, self.self_port, str(header.src_ip), header.src_port, INNER_HEADER_SIZE, 'A', header.seq_no, 0).to_bytes()
            self.sock.sendto(packet_ack, (self.emulator_ip, self.emulator_port))
            print("Acknowledged packet", header)
            return False
        else:
            assert header.packet_type == 'E'
            self.end_seq_no = header.seq_no
            print("End packet", header)
            return True

    def write_file(self):
        print("Writing file", self.file_id)
        for i in range(1, self.end_seq_no):
            self.f_out.write(self.packet_chunks[i])
        self.packet_chunks.clear()


def read_tacker():
    with open(TRACKER_FILE) as f_in:
        lines = f_in.readlines()

    for line in lines:
        tokens = str(line).strip("\n ").split(" ")
        TRACKER_TABLE[tokens[0]][int(tokens[1])] = (tokens[2], int(tokens[3]))


def receive_file(sock: socket.socket, data_exchange_list: Dict[Tuple[ipaddress.IPv4Address, int], SenderDataExchange]):
    completed_senders: List[Tuple[ipaddress.IPv4Address, int]] = list()
    while len(completed_senders) < len(data_exchange_list):
        read_sockets, _, _ = select.select([sock], [], [], 0)
        if sock not in read_sockets:
            continue
        packet = sock.recv(BUF_SIZE)
        header: Header = Header.from_bytes(packet[:HEADER_SIZE])
        if data_exchange_list[(header.src_ip, header.src_port)].register_packet(packet):
            completed_senders.append((header.dst_ip, header.dst_port))
    print("Receiving file complete")
    for sender_exchange in sorted(data_exchange_list.values()):
        sender_exchange.write_file()


def send_file_request(port: int, filename: str, emulator_name: str, emulator_port: int, window: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((socket.gethostname(), port))
    sock.setblocking(False)

    assert filename in TRACKER_TABLE, "Filename not in tracker"

    with open(filename, 'wb') as f_out:
        file_table = TRACKER_TABLE[filename]
        i = 1
        data_exchange_list = dict()
        while i in file_table:
            src_ip = socket.gethostbyname(socket.gethostname())
            dst_ip, dst_port = socket.gethostbyname(file_table[i][0]), file_table[i][1]
            outer_len = len(bytes(filename, "utf-8")) + HEADER_SIZE
            packet = Header(1, src_ip, port, dst_ip, dst_port, outer_len, 'R', 0, window).to_bytes() + bytes(filename, "utf-8")
            sock.sendto(packet, (socket.gethostbyname(emulator_name), emulator_port))
            data_exchange_list[(ipaddress.IPv4Address(dst_ip), dst_port)] = SenderDataExchange(f_out, port, emulator_name, emulator_port, i, sock)
            i += 1
        receive_file(sock, data_exchange_list)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='File Requester')
    parser.add_argument('-p', '--port', type=int, help='port on which the requester waits for packets', required=True)
    parser.add_argument('-o', '--file_option', type=str, help='name of the file that is being requested', required=True)
    parser.add_argument('-f', '--f_hostname', type=str, help='the host name of the emulator', required=True)
    parser.add_argument('-e', '--f_port', type=int, help='the port of the emulator', required=True)
    parser.add_argument('-w', '--window', type=int, help='the requesters window size', required=True)

    args = parser.parse_args()
    signal.signal(signal.SIGINT, lambda x, y: sys.exit(1))
    read_tacker()
    send_file_request(args.port, args.file_option, args.f_hostname, args.f_port, args.window)
