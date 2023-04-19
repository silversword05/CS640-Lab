import argparse
import ipaddress
import select
import socket
import struct
from typing import Union

BUF_SIZE = 1024
TTL_MAX = 50


class Header:
    header_struct_format = '!IHIHcIHI?'
    header_size = struct.calcsize(header_struct_format)

    def __init__(self, src_ip: Union[int, str, ipaddress.IPv4Address], src_port: int, dst_ip: Union[int, str, ipaddress.IPv4Address], dst_port: int,
                 packet_type: str, seq_no: int, ttl: int, payload_length: int, wrapped: bool):
        self.src_ip = ipaddress.IPv4Address(src_ip)
        self.src_port = src_port
        self.dst_ip = ipaddress.IPv4Address(dst_ip)
        self.dst_port = dst_port
        self.packet_type = packet_type
        self.seq_no = seq_no
        self.ttl = ttl
        self.payload_length = payload_length
        self.wrapped: bool = wrapped

    @classmethod
    def from_bytes(cls, header_data: bytes):
        assert len(header_data) == cls.header_size
        data_tuple = struct.unpack(cls.header_struct_format, header_data)
        return cls(int(data_tuple[0]), int(data_tuple[1]), int(data_tuple[2]), int(data_tuple[3]), data_tuple[4].decode("utf-8"), int(data_tuple[5]),
                   int(data_tuple[6]), int(data_tuple[7]), bool(data_tuple[8]))

    def to_bytes(self):
        assert self.src_ip != 0
        return struct.pack(self.header_struct_format, int(self.src_ip), self.src_port, int(self.dst_ip), self.dst_port,
                           str(self.packet_type).encode(), self.seq_no, self.ttl, self.payload_length, self.wrapped)

    def __str__(self):
        return (f"Header(src_ip={self.src_ip},src_port={self.src_port},dst_ip={self.dst_ip},dst_port={self.dst_port},"
                f"packet_type={self.packet_type},seq_no={self.seq_no},ttl={self.ttl},payload-len={self.payload_length}),wrapped={self.wrapped}")


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


class RouteTrace:
    def __init__(self, self_port: int, src_ip: Union[int, str, ipaddress.IPv4Address], src_port: int, dst_ip: Union[int, str, ipaddress.IPv4Address],
                 dst_port: int, debug: bool):
        self.self_port: int = self_port
        self.self_ip = ipaddress.IPv4Address(socket.gethostbyname(socket.gethostname()))
        self.src_ip = ipaddress.IPv4Address(src_ip)
        self.src_port = src_port
        self.dst_ip = ipaddress.IPv4Address(dst_ip)
        self.dst_port = dst_port
        self.debug: bool = debug

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('', self_port))
        self.sock.setblocking(False)
        self.__register_self__()

    def __register_self__(self):
        header: Header = Header(self.self_ip, self.self_port, self.src_ip, self.src_port, 'A', 0, 1, 0, False)
        self.sock.sendto(header.to_bytes(), (str(self.src_ip), int(self.src_port)))

    def __get_packet__(self) -> Header:
        while True:
            read_sockets, _, _ = select.select([self.sock], [], [], 0)
            if self.sock in read_sockets:
                break
        packet = self.sock.recv(BUF_SIZE)
        header = Header.from_bytes(packet[:Header.header_size])
        assert header.packet_type == 'T'
        if self.debug:
            print(f"INFO: Received {header.src_ip}:{header.src_port} -> {header.dst_ip}:{header.dst_port} TTL={header.ttl}")
        return header

    def __send_trace_packet__(self, ttl: int):
        header = Header(self.self_ip, self.self_port, self.dst_ip, self.dst_port, 'T', 0, ttl, 0, False)
        tunnel_header = TunnelHeader(self.dst_ip, self.dst_port)
        if self.debug:
            print(f"INFO: Sent {header.src_ip}:{header.src_port} -> {header.dst_ip}:{header.dst_port} TTL={header.ttl}")
        packet: bytes = header.to_bytes() + tunnel_header.to_bytes()
        self.sock.sendto(packet, (str(self.src_ip), self.src_port))

    def perform_trace(self):
        ttl = 0
        curr_ip = self.self_ip
        curr_port = self.self_port

        while not (curr_ip == self.dst_ip and curr_port == self.dst_port):
            self.__send_trace_packet__(ttl)
            received_header: Header = self.__get_packet__()
            curr_ip = received_header.src_ip
            curr_port = received_header.src_port
            print(f"Responder Info {received_header.src_ip}:{received_header.src_port}")
            ttl += 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='Route-trace')
    parser.add_argument('-a', '--route_trace_port', type=int, help='the port of the route trace', required=True)
    parser.add_argument('-b', '--src_host', type=str, help='the emulator IP to connect', required=True)
    parser.add_argument('-c', '--src_port', type=int, help='the emulator port to connect', required=True)
    parser.add_argument('-d', '--dst_host', type=str, help='the destination emulator IP', required=True)
    parser.add_argument('-e', '--dst_port', type=int, help='the destination emulator port', required=True)
    parser.add_argument('-f', '--debug', type=int, help='print packet received info', required=True)

    args = parser.parse_args()
    route_trace = RouteTrace(int(args.route_trace_port), str(args.src_host), int(args.src_port), str(args.dst_host), int(args.dst_port),
                             bool(args.debug == 1))
    print(bool(args.debug))
    route_trace.perform_trace()
