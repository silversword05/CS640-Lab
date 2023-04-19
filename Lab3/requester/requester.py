import argparse
import ipaddress
import socket
import struct
from collections import defaultdict
from datetime import datetime
from typing import Union, BinaryIO

BUF_SIZE = 1024
TTL_MAX = 50
IP_PORT_SEPARATOR = ","
TRACKER_FILE = 'tracker.txt'


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


def print_summary(sender_addr: ipaddress.IPv4Address, sender_port: int, total_packets: int, total_bytes: int, total_duration: int):
    print()
    print("Summary")
    print(f"sender addr:             {sender_addr}:{sender_port}")
    print(f"Total Data packets:      {total_packets}")
    print(f"Total Data bytes:        {total_bytes}")
    print(f"Average packets/second:  {round(total_packets * 1000 / total_duration) if total_duration != 0 else 0}")
    print(f"Duration of the test:    {total_duration}  ms")
    print()


class Requester:
    class SenderAddress:
        def __init__(self, sender_addr: str, sender_emulator_addr:
        str):
            sender_tokens = sender_addr.split(IP_PORT_SEPARATOR)
            self.sender_ip: ipaddress.IPv4Address = ipaddress.IPv4Address(sender_tokens[0])
            self.sender_port: int = int(sender_tokens[1])

            sender_emulator_tokens = sender_emulator_addr.split(IP_PORT_SEPARATOR)
            self.sender_emulator_ip: ipaddress.IPv4Address = ipaddress.IPv4Address(sender_emulator_tokens[0])
            self.sender_emulator_port: int = int(sender_emulator_tokens[1])

        def __str__(self):
            return f"sender={self.sender_ip}:{self.sender_port} emulator={self.sender_emulator_ip}:{self.sender_emulator_port}"

    def __init__(self, self_port: int, src_ip: Union[int, str, ipaddress.IPv4Address], src_port: int):
        self.self_port = self_port
        self.self_ip = ipaddress.IPv4Address(socket.gethostbyname(socket.gethostname()))
        self.src_emulator_ip = ipaddress.IPv4Address(src_ip)
        self.src_emulator_port = src_port
        self.tracker_table: defaultdict[str, defaultdict[int, Requester.SenderAddress]] = defaultdict(lambda: defaultdict(Requester.SenderAddress))

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('', self_port))
        self.__register_self__()
        self.__read_tracker__()

    def __register_self__(self):
        header: Header = Header(self.self_ip, self.self_port, self.src_emulator_ip, self.src_emulator_port, 'A', 1, 0, False)
        self.sock.sendto(header.to_bytes(), (str(self.src_emulator_ip), int(self.src_emulator_port)))

    def __read_tracker__(self):
        with open(TRACKER_FILE, 'r') as f_in:
            for line in f_in.readlines():
                if line.startswith('#'):
                    continue
                tokens = str(line).strip("\n ").split(" ")
                self.tracker_table[tokens[0]][int(tokens[1])] = Requester.SenderAddress(tokens[3], tokens[2])

    def __receive_file__(self, file_out: BinaryIO):
        packet_count = byte_count = 0
        start: datetime | None = None
        while True:
            packet: bytes = self.sock.recv(BUF_SIZE)
            if start is None:
                start = datetime.now()
            header: Header = Header.from_bytes(packet[:Header.header_size])
            assert header.dst_ip == self.self_ip and header.dst_port == self.self_port
            assert header.packet_type in ['D', 'E']
            if header.packet_type == 'E':
                end = datetime.now()
                print_summary(header.src_ip, header.src_port, packet_count, byte_count, int((end - start).total_seconds() * 1000))
                break
            data = packet[Header.header_size:]
            file_out.write(data)
            packet_count += 1
            byte_count += len(data)
            print(f"Received packet {packet_count}", end='\r')

    def send_request_packet(self, filename: str):
        assert filename in self.tracker_table
        with open(filename, 'wb') as f_out:
            file_table = self.tracker_table[filename]
            i = 1
            while i in file_table:
                payload: str = filename + "\n" + f"{self.src_emulator_ip}{IP_PORT_SEPARATOR}{self.src_emulator_port}"
                header = Header(self.self_ip, self.self_port, file_table[i].sender_ip, file_table[i].sender_port, 'R', TTL_MAX, len(payload), False)
                tunnel_header = TunnelHeader(file_table[i].sender_emulator_ip, file_table[i].sender_emulator_port)
                packet: bytes = header.to_bytes() + tunnel_header.to_bytes() + payload.encode("utf-8")
                self.sock.sendto(packet, (str(self.src_emulator_ip), int(self.src_emulator_port)))
                self.__receive_file__(f_out)
                i += 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='File Requester')
    parser.add_argument('-p', '--port', type=int, help='port on which the requester waits for packets', required=True)
    parser.add_argument('-o', '--file_option', type=str, help='name of the file that is being requested', required=True)
    parser.add_argument('-b', '--src_host', type=str, help='the emulator IP to connect', required=True)
    parser.add_argument('-c', '--src_port', type=int, help='the emulator port to connect', required=True)

    args = parser.parse_args()
    requester = Requester(int(args.port), str(args.src_host), int(args.src_port))
    requester.send_request_packet(str(args.file_option))

# python3 requester.py -p 4001 -o split.txt -b 127.0.0.1 -c 4000
