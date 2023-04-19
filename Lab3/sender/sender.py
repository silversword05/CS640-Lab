import argparse
import copy
import ipaddress
import socket
import struct
import time
from typing import Union, List

BUF_SIZE = 1024
TTL_MAX = 50
IP_PORT_SEPARATOR = ","


class Header:
    header_struct_format = '!IHIHcHI?'
    header_size = struct.calcsize(header_struct_format)

    def __init__(self, src_ip: Union[int, str, ipaddress.IPv4Address], src_port: int, dst_ip: Union[int, str, ipaddress.IPv4Address], dst_port: int,
                 packet_type: str, ttl: int, payload_length: int, wrapped: bool):
        self.src_ip = ipaddress.IPv4Address(src_ip)
        self.src_port = src_port
        self.dst_ip = ipaddress.IPv4Address(dst_ip)
        self.dst_port = dst_port
        self.packet_type = packet_type
        self.ttl = ttl
        self.payload_length = payload_length
        self.wrapped: bool = wrapped

    @classmethod
    def from_bytes(cls, header_data: bytes):
        assert len(header_data) == cls.header_size
        data_tuple = struct.unpack(cls.header_struct_format, header_data)
        return cls(int(data_tuple[0]), int(data_tuple[1]), int(data_tuple[2]), int(data_tuple[3]), data_tuple[4].decode("utf-8"),
                   int(data_tuple[5]), int(data_tuple[6]), bool(data_tuple[7]))

    def to_bytes(self):
        assert self.src_ip != 0
        return struct.pack(self.header_struct_format, int(self.src_ip), self.src_port, int(self.dst_ip), self.dst_port,
                           str(self.packet_type).encode(), self.ttl, self.payload_length, self.wrapped)

    def __str__(self):
        return (f"Header(src_ip={self.src_ip},src_port={self.src_port},dst_ip={self.dst_ip},dst_port={self.dst_port},"
                f"packet_type={self.packet_type},ttl={self.ttl},payload-len={self.payload_length},wrapped={self.wrapped})")


class TunnelHeader:
    header_struct_format = '!IH'
    header_size = struct.calcsize(header_struct_format)

    def __init__(self, dst_emulator_ip: Union[int, str, ipaddress.IPv4Address], dst_emulator_port: int):
        self.dst_emulator_ip = ipaddress.IPv4Address(dst_emulator_ip)
        self.dst_emulator_port = dst_emulator_port

    @classmethod
    def from_bytes(cls, header_data: bytes):
        assert len(header_data) == cls.header_size
        data_tuple = struct.unpack(cls.header_struct_format, header_data)
        return cls(int(data_tuple[0]), int(data_tuple[1]))

    def to_bytes(self):
        assert self.dst_emulator_ip != 0
        return struct.pack(self.header_struct_format, int(self.dst_emulator_ip), int(self.dst_emulator_port))

    def __str__(self):
        return f"Dst-Emulator={self.dst_emulator_ip}:{self.dst_emulator_port}"


def get_reverse_header(old_header: Header) -> Header:
    new_header = copy.deepcopy(old_header)
    new_header.ttl = 1
    new_header.src_ip = old_header.dst_ip
    new_header.src_port = old_header.dst_port
    new_header.dst_ip = old_header.src_ip
    new_header.dst_port = old_header.src_port
    return new_header


class Sender:
    def __init__(self, self_port: int, requester_port: int, rate: float, initial_seq_no: int, length: int,
                 src_ip: Union[int, str, ipaddress.IPv4Address], src_port: int):
        self.self_port = self_port
        self.self_ip = ipaddress.IPv4Address(socket.gethostbyname(socket.gethostname()))
        self.src_ip = ipaddress.IPv4Address(src_ip)
        self.src_port = src_port
        self.requester_port = requester_port
        self.rate = rate
        self.initial_seq_no = initial_seq_no
        self.length = length

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('', self_port))
        self.__register_self__()

    def __register_self__(self):
        header: Header = Header(self.self_ip, self.self_port, self.src_ip, self.src_port, 'A', 1, 0, False)
        self.sock.sendto(header.to_bytes(), (str(self.src_ip), int(self.src_port)))

    def __send_packet__(self, packet_type: str, payload: bytes, requester_header: Header, requester_emulator_tokens: List[str]):
        requester_emulator_ip, requester_emulator_port = ipaddress.IPv4Address(requester_emulator_tokens[0]), int(requester_emulator_tokens[1])
        assert packet_type in ['D', 'E']
        assert requester_header.dst_ip == self.self_ip and requester_header.dst_port == self.self_port

        header = get_reverse_header(requester_header)
        header.packet_type = packet_type
        header.ttl = TTL_MAX
        header.payload_length = len(payload)
        tunnel_header = TunnelHeader(requester_emulator_ip, requester_emulator_port)
        packet: bytes = header.to_bytes() + tunnel_header.to_bytes() + payload
        self.sock.sendto(packet, (str(self.src_ip), int(self.src_port)))
        time.sleep(1 / self.rate)

    def __serve_file__(self, request_string: str, requester_header: Header):
        lines = str(request_string).splitlines()
        filename = str(lines[0]).strip(" \n")
        requester_emulator_tokens: List[str] = str(lines[1]).split(IP_PORT_SEPARATOR)

        with open(filename, 'rb') as f:
            while byte := f.read(self.length):
                self.__send_packet__('D', byte, requester_header, requester_emulator_tokens)
            self.__send_packet__('E', bytes('', "utf-8"), requester_header, requester_emulator_tokens)

    def look_for_request_packets(self):
        while True:
            packet: bytes = self.sock.recv(BUF_SIZE)
            header: Header = Header.from_bytes(packet[:Header.header_size])
            assert header.packet_type == 'R' and not header.wrapped
            self.__serve_file__(packet[Header.header_size:].decode("utf-8"), header)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='File Sender')
    parser.add_argument('-p', '--port', type=int, help='port on which the sender waits for requests', required=True)
    parser.add_argument('-g', '--requester_port', type=int, help='port on which the requester is waiting', required=True)
    parser.add_argument('-r', '--rate', type=float, help='number of packets to be sent per second', required=True)
    parser.add_argument('-q', '--seq_no', type=int, help='initial sequence of the packet exchange', required=True)
    parser.add_argument('-l', '--length', type=int, help='length of the payload (in bytes) in the packets', required=True)
    parser.add_argument('-b', '--src_host', type=str, help='the emulator IP to connect', required=True)
    parser.add_argument('-c', '--src_port', type=int, help='the emulator port to connect', required=True)

    args = parser.parse_args()
    sender = Sender(int(args.port), int(args.requester_port), float(args.rate), int(args.seq_no), int(args.length), str(args.src_host),
                    int(args.src_port))
    sender.look_for_request_packets()

# python3 sender.py -p 5001 -g 4001 -r 1 -q 100 -l 100 -b 127.0.0.1 -c 5000
