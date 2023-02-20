import argparse
import socket
import struct

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


def receive_file(receive_port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', receive_port))

    while True:
        packet, from_address = sock.recvfrom(BUF_SIZE)
        header, data = Header(*struct.unpack("!c2I", packet[:9])), packet[9:]
        print("received message: %s from %s" % (header, from_address))
        print(len(data))
        if header.type == 'E':
            break


def send_file_request(receive_port: int, filename: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    assert filename in TRACKER_TABLE, "Filename not in tracker"
    file_table = TRACKER_TABLE[filename]
    i = 1
    while i in file_table:
        packet = struct.pack("!c2I", b'R', socket.htonl(0), socket.htonl(0)) + bytes(filename, "utf-8")
        sock.sendto(packet, (socket.gethostbyname(file_table[i][0]), file_table[i][1]))
        receive_file(receive_port)
        i += 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='File Requester')
    parser.add_argument('-p', '--port', type=int, help='port on which the requester waits for packets', required=True)
    parser.add_argument('-o', '--file_option', type=str, help='name of the file that is being requested', required=True)

    args = parser.parse_args()
    read_tacker()
    send_file_request(args.port, args.file_option)
