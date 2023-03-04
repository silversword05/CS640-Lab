import argparse
import socket
import struct
from datetime import datetime

from collections import defaultdict

TRACKER_FILE = 'tracker.txt'
TRACKER_TABLE = defaultdict(lambda: defaultdict(tuple))
BUF_SIZE = 1024 * 5


class Header:
    def __init__(self, packet_type: bytes, seq_no, length):
        self.type = packet_type.decode("utf-8")
        self.seq_no = socket.ntohl(seq_no)
        self.length = socket.ntohl(length)

    def __str__(self):
        return f"Header=(type={self.type},seq_no={self.seq_no},length={self.length}"


def read_tacker():
    with open(TRACKER_FILE) as f_in:
        lines = f_in.readlines()

    for line in lines:
        tokens = str(line).strip("\n ").split(" ")
        TRACKER_TABLE[tokens[0]][int(tokens[1])] = (tokens[2], int(tokens[3]))


def print_packet(packet_type: str, sender_addr: str, sender_from_port: int, seq_num: int, payload: bytes):
    if packet_type == 'D':
        print("DATA Packet")
    if packet_type == 'E':
        print("End Packet")
    print(f"recv time:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}")
    print(f"sender addr:  {sender_addr}:{sender_from_port}")
    print(f"sequence:     {seq_num}")
    print(f"length:       {len(payload)}")
    print(f"payload:      {payload[:4].decode('utf-8')}")
    print()


def print_summary(sender_addr: str, sender_from_port: int, total_packets: int, total_bytes: int, total_duration: int):
    print("Summary")
    print(f"sender addr:             {sender_addr}:{sender_from_port}")
    print(f"Total Data packets:      {total_packets}")
    print(f"Total Data bytes:        {total_bytes}")
    print(f"Average packets/second:  {int(total_packets * 1000 / total_duration) if total_duration != 0 else 0}")
    print(f"Duration of the test:    {total_duration}  ms")
    print()


def receive_file(sock: socket, file_out):
    packet_count = byte_count = 0
    start = end = None
    while True:
        packet, from_address = sock.recvfrom(BUF_SIZE)
        if start is None:
            start = datetime.now()
        header, data = Header(*struct.unpack("!c2I", packet[:9])), packet[9:]
        print_packet(header.type, from_address[0], from_address[1], header.seq_no, data)
        if header.type == 'E':
            end = datetime.now()
            print_summary(from_address[0], from_address[1], packet_count, byte_count, int((end - start).total_seconds() * 1000))
            break
        file_out.write(data)
        packet_count += 1
        byte_count += len(data)


def send_file_request(receive_port: int, filename: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', receive_port))

    assert filename in TRACKER_TABLE, "Filename not in tracker"

    with open(filename, 'wb') as f_out:
        file_table = TRACKER_TABLE[filename]
        i = 1
        while i in file_table:
            packet = struct.pack("!c2I", b'R', socket.htonl(0), socket.htonl(0)) + bytes(filename, "utf-8")
            sock.sendto(packet, (socket.gethostbyname(file_table[i][0]), file_table[i][1]))
            receive_file(sock, f_out)
            i += 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='File Requester')
    parser.add_argument('-p', '--port', type=int, help='port on which the requester waits for packets', required=True)
    parser.add_argument('-o', '--file_option', type=str, help='name of the file that is being requested', required=True)

    args = parser.parse_args()
    read_tacker()
    send_file_request(args.port, args.file_option)
