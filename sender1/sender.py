import argparse
import socket
import struct

BUF_SIZE = 1024


class Header:
    def __init__(self, packet_type, seq_no, length):
        self.type = str(packet_type)
        self.seq_no = socket.ntohl(seq_no)
        self.length = socket.ntohl(length)

    def __str__(self):
        return f"Header=(type={self.type},seq_no={self.seq_no},length={self.length}"


def send_file(requester_port: int, rate: int, seq_no: int, length: int, filename: str):
    with open(filename, 'rb') as f:
        while byte := f.read(length):
            print(len(byte))


def receive_request(port: int, requester_port: int, rate: int, seq_no: int, length: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', port))

    packet, from_address = sock.recvfrom(BUF_SIZE)
    header, data = Header(*struct.unpack("!c2I", packet[:9])), packet[9:]
    print("received message: %s from %s" % (header, from_address))
    print(data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='File Sender')
    parser.add_argument('-p', '--port', type=int, help='port on which the sender waits for requests', required=True)
    parser.add_argument('-g', '--requester_port', type=int, help='port on which the requester is waiting', required=True)
    parser.add_argument('-r', '--rate', type=float, help='number of packets to be sent per second', required=True)
    parser.add_argument('-q', '--seq_no', type=int, help='initial sequence of the packet exchange', required=True)
    parser.add_argument('-l', '--length', type=int, help='length of the payload (in bytes) in the packets', required=True)

    args = parser.parse_args()
    receive_request(args.port, args.requester_port, args.rate, args.seq_no, args.length)
