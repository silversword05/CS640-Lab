import argparse
import copy
import heapq as heap
import ipaddress
import logging
import select
import socket
import struct
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Union, List, Tuple, Dict, Set

IP_PORT_SEPARATOR = ","
BUF_SIZE = 1024
PING_INTERVAL = timedelta(seconds=0.5)
PING_SLEEP_MS = 1
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
                f"packet_type={self.packet_type},seq_no={self.seq_no},ttl={self.ttl},payload-len={self.payload_length},wrapped={self.wrapped})")


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


class LinkStateIndividual:
    def __init__(self, ip: Union[int, str], port: int):
        self.seq_no = 0
        self.source_ip = ipaddress.IPv4Address(ip)
        self.source_port = port
        self.neighbour_list: Set[Tuple[ipaddress.IPv4Address, int]] = set()

    @classmethod
    def populate_neighbours(cls, line: str):
        tokens = str(line).split(" ")
        start_ip, start_port = str(tokens[0]).split(IP_PORT_SEPARATOR)
        link_state_individual = cls(start_ip, int(start_port))
        for token in tokens[1:]:
            neighbour_ip, neighbour_port = str(token).split(IP_PORT_SEPARATOR)
            neighbour_ip = socket.gethostbyname(neighbour_ip)
            link_state_individual.neighbour_list.add((ipaddress.IPv4Address(neighbour_ip), int(neighbour_port)))
        logging.info("Populated neighbours %s", str(link_state_individual))
        return link_state_individual

    def update_neighbours(self, line: str, new_seq_no: int):
        if self.seq_no < new_seq_no:
            self.seq_no = new_seq_no
            tokens = str(line).split(" ")
            start_ip, start_port = str(tokens[0]).split(IP_PORT_SEPARATOR)
            assert self.source_ip == ipaddress.IPv4Address(start_ip) and self.source_port == int(start_port)
            self.neighbour_list.clear()
            for token in tokens[1:]:
                neighbour_ip, neighbour_port = str(token).split(IP_PORT_SEPARATOR)
                self.neighbour_list.add((ipaddress.IPv4Address(neighbour_ip), int(neighbour_port)))
            logging.info("Updated neighbours %s", str(self))

    def __add__(self, new_entries: List[Tuple[ipaddress.IPv4Address, int]]):
        add_success = False
        for new_entry in new_entries:
            add_success = add_success or (new_entry not in self.neighbour_list)
            self.neighbour_list.add(new_entry)
        if add_success:
            self.seq_no += 1
            logging.info("Added new entries %s %s %s", self.seq_no, f"{self.source_ip}:{self.source_port}", new_entries)
        return add_success

    def __sub__(self, new_entries: List[Tuple[ipaddress.IPv4Address, int]]):
        remove_success = False
        for new_entry in new_entries:
            remove_success = remove_success or (new_entry in self.neighbour_list)
            self.neighbour_list.remove(new_entry)
        if remove_success:
            self.seq_no += 1
            logging.info("Removed new entries %s %s %s", self.seq_no, f"{self.source_ip}:{self.source_port}", new_entries)
        return remove_success

    def __str__(self):
        return f"{self.seq_no} {self.source_ip}:{self.source_port} -> {','.join([str(x) + ':' + str(y) for x, y in self.neighbour_list])}"

    def get_payload_str(self):
        res = f"{self.source_ip}{IP_PORT_SEPARATOR}{self.source_port}\n"
        res += f"{self.source_ip}{IP_PORT_SEPARATOR}{self.source_port} " + " ".join(
            [f"{elem[0]}{IP_PORT_SEPARATOR}{elem[1]}" for elem in self.neighbour_list])
        return res


class LinkGraph:
    def __init__(self, ip: Union[int, str, ipaddress.IPv4Address], port: int, topology_file: str):
        self.starting_node = (ipaddress.IPv4Address(ip), port)
        self.link_state_map: Dict[Tuple[ipaddress.IPv4Address, int], LinkStateIndividual] = dict()
        self.forwarding_table: Dict[Tuple[ipaddress.IPv4Address, int], Tuple[ipaddress.IPv4Address, int]] = dict()
        self.__read_topology__(topology_file)
        self.build_forward_table()

    def __add__(self, new_node: LinkStateIndividual):
        assert new_node not in self.link_state_map
        logging.info("Added new link state %s", new_node)
        self.link_state_map[(new_node.source_ip, new_node.source_port)] = new_node
        return self

    def __dijkstra__(self):
        assert len(self.forwarding_table) == 0

        visited: Set[Tuple[ipaddress.IPv4Address, int]] = set()
        parents_map: Dict[Tuple[ipaddress.IPv4Address, int], Tuple[ipaddress.IPv4Address, int]] = dict()
        pq: List[Tuple[float, Tuple[ipaddress.IPv4Address, int]]] = list()
        node_costs: defaultdict[Tuple[ipaddress.IPv4Address, int], float] = defaultdict(lambda: float('inf'))

        node_costs[self.starting_node] = 0
        heap.heappush(pq, (0, self.starting_node))

        while pq:
            _, node = heap.heappop(pq)
            visited.add(node)

            if node not in self.link_state_map:
                continue

            for adj_node in self.link_state_map[node].neighbour_list:
                if adj_node in visited:
                    continue

                new_cost: float = node_costs[node] + 1
                if node_costs[adj_node] > new_cost:
                    parents_map[adj_node] = node
                    node_costs[adj_node] = new_cost
                    heap.heappush(pq, (new_cost, adj_node))

        logging.info("Ran dijkstra %s", parents_map)
        return parents_map, visited

    def build_forward_table(self):
        logging.info("Building forwarding table")
        self.forwarding_table.clear()
        parents_map, visited = self.__dijkstra__()

        def set_forwarding_table(curr_node: Tuple[ipaddress.IPv4Address, int]):
            if parents_map[curr_node] in self.forwarding_table:
                self.forwarding_table[curr_node] = self.forwarding_table[parents_map[curr_node]]
                return self.forwarding_table[curr_node]

            if parents_map[curr_node] == self.starting_node:
                return curr_node

            self.forwarding_table[curr_node] = set_forwarding_table(parents_map[curr_node])
            return self.forwarding_table[curr_node]

        for each_node in visited:
            if each_node == self.starting_node:
                continue
            self.forwarding_table[each_node] = set_forwarding_table(each_node)

        self.__print_topology__()
        self.__print_forwarding_table__()

    def __read_topology__(self, topology_file: str):
        self.link_state_map.clear()
        with open(topology_file, 'r') as f_in:
            for line in f_in.readlines():
                if line.startswith('#'):
                    continue
                link_state_individual: LinkStateIndividual = LinkStateIndividual.populate_neighbours(line)
                self.__add__(link_state_individual)

    def __print_topology__(self):
        print("Topology:")
        logging.info("Topology: ")
        for node in self.link_state_map:
            print(self.link_state_map[node])
            logging.info("%s", self.link_state_map[node])

    def __print_forwarding_table__(self):
        print("Forwarding Table:")
        logging.info("Forwarding Table:")
        for dst_hop in self.forwarding_table:
            next_hop = self.forwarding_table[dst_hop]
            print(f"{str(dst_hop[0])}:{dst_hop[1]}", f"{str(next_hop[0])}:{next_hop[1]}")
            logging.info("%s %s", f"{str(dst_hop[0])}:{dst_hop[1]}", f"{str(next_hop[0])}:{next_hop[1]}")

    def update_link_states(self, start_ip: ipaddress.IPv4Address, start_port: int, line: str, new_seq_no: int) -> int:
        if (start_ip, start_port) not in self.link_state_map:
            self.__add__(LinkStateIndividual(str(start_ip), start_port))
        old_seq_no = self.link_state_map[(start_ip, start_port)].seq_no
        self.link_state_map[(start_ip, start_port)].update_neighbours(line, new_seq_no)
        logging.info("Link state update try %d %d", new_seq_no, old_seq_no)
        if new_seq_no > old_seq_no:
            self.build_forward_table()
        return old_seq_no

    def find_next_hop(self, header: Header) -> Union[Tuple[ipaddress.IPv4Address, int], None]:
        if (header.dst_ip, header.dst_port) not in self.forwarding_table:
            return None
        return self.forwarding_table[(header.dst_ip, header.dst_port)]


class LinkMaintenance:
    class PingTime:
        def __init__(self):
            self.ping_received = datetime.now()
            self.ping_sent = datetime.now()

        def __str__(self):
            return f"Ping received={self.ping_received} sent={self.ping_sent}"

    def __init__(self, link_graph: LinkGraph, initial_neighbours: Set[Tuple[ipaddress.IPv4Address, int]], sock: socket.socket,
                 self_ip: ipaddress.IPv4Address, self_port: int):
        self.link_graph: LinkGraph = link_graph
        self.link_pings: defaultdict[Tuple[ipaddress.IPv4Address, int], LinkMaintenance.PingTime] = defaultdict(lambda: LinkMaintenance.PingTime())
        for neighbour in initial_neighbours:
            self.link_pings[neighbour] = LinkMaintenance.PingTime()
        self.registered_clients: Set[Tuple[ipaddress.IPv4Address, int]] = set()
        self.sock = sock
        self.self_ip = self_ip
        self.self_port = self_port

    def __send_source_ping__(self, start_ip: ipaddress.IPv4Address, start_port: int, header: Header):
        new_header = get_reverse_header(header)
        payload = self.link_graph.link_state_map[(start_ip, start_port)].get_payload_str()
        new_packet = new_header.to_bytes() + payload.encode("utf-8")
        logging.info("Sending source ping %s", new_header)
        self.sock.sendto(new_packet, (str(new_header.dst_ip), new_header.dst_port))

    def __send_neighbour_ping__(self, packet: bytes):
        header = Header.from_bytes(packet[:Header.header_size])
        assert header.packet_type == 'L'
        new_header = get_reverse_header(header)

        for node in self.link_pings.keys():
            if node[0] == header.src_ip and node[1] == header.src_port:
                continue
            new_header.dst_ip = node[0]
            new_header.dst_port = node[1]
            new_packet = new_header.to_bytes() + packet[Header.header_size:]
            logging.info("Sending neighbour ping %s", new_header)
            self.sock.sendto(new_packet, (str(node[0]), node[1]))

    def create_routes(self, packet: bytes):
        header = Header.from_bytes(packet[:Header.header_size])
        logging.info("Create route packet received: %s", header)
        assert header.packet_type == 'L'
        assert header.dst_ip == self.self_ip and header.dst_port == self.self_port
        assert not (header.src_ip == self.self_ip and header.src_port == self.self_port)

        if self.link_graph.link_state_map[(self.self_ip, self.self_port)] + [(header.src_ip, header.src_port)]:
            self.link_graph.build_forward_table()
        self.link_pings[(header.src_ip, header.src_port)].ping_received = datetime.now()

        payload = packet[Header.header_size:]
        lines = payload.decode("utf-8").splitlines()
        tokens = str(lines[0]).split(IP_PORT_SEPARATOR)
        start_ip, start_port = ipaddress.IPv4Address(tokens[0]), int(tokens[1])

        old_seq_no: int = self.link_graph.update_link_states(start_ip, start_port, lines[1], header.seq_no)
        logging.info("Seq No in create route %s %d %d %d", start_ip, start_port, old_seq_no, header.seq_no)
        if old_seq_no > header.seq_no:
            self.__send_source_ping__(start_ip, start_port, header)
        elif old_seq_no < header.seq_no:
            self.__send_neighbour_ping__(packet)

    def send_pings(self):
        self_record = self.link_graph.link_state_map[(self.self_ip, self.self_port)]
        payload = self_record.get_payload_str()

        dead_nodes: List[Tuple[ipaddress.IPv4Address, int]] = list()
        for node in self.link_pings.keys():
            if datetime.now() > self.link_pings[node].ping_sent + PING_INTERVAL:
                logging.info("Ping times %s %s %s", node, datetime.now(), self.link_pings[node].ping_sent)
                header = Header(self.self_ip, self.self_port, node[0], node[1], 'L', self_record.seq_no, 1, len(payload), False)
                new_packet = header.to_bytes() + payload.encode("utf-8")
                self.sock.sendto(new_packet, (str(node[0]), int(node[1])))
                time.sleep(PING_SLEEP_MS / 1000)
                self.link_pings[node].ping_sent = datetime.now()
            if datetime.now() > self.link_pings[node].ping_received + 6 * PING_INTERVAL:
                logging.info("Ping miss %s %s %s", node, datetime.now(), self.link_pings[node].ping_received)
                dead_nodes.append(node)

        for node in dead_nodes:
            self.link_pings.pop(node)
        if self.link_graph.link_state_map[(self.self_ip, self.self_port)] - dead_nodes:
            self.link_graph.build_forward_table()

    def drop_packet(self, packet: bytes):
        header = Header.from_bytes(packet[:Header.header_size])
        logging.info("Drop packets %s", header)
        assert header.ttl == 0
        if header.packet_type != 'T':
            return

        if (header.src_ip, header.src_port) in self.registered_clients:
            logging.info("Dropping client packet %s", header)
            new_inner_header: Header = get_reverse_header(header)  # No outer header exists
            new_inner_header.src_ip = self.self_ip
            new_inner_header.src_port = self.self_port
            new_packet: bytes = new_inner_header.to_bytes() + packet[Header.header_size + TunnelHeader.header_size:]
            self.sock.sendto(new_packet, (str(new_inner_header.dst_ip), int(new_inner_header.dst_port)))
        else:
            logging.info("Dropping Normal packet %s", header)
            new_outer_header = get_reverse_header(header)
            new_outer_header.src_ip = self.self_ip
            new_outer_header.src_port = self.self_port
            new_outer_header.ttl = TTL_MAX

            inner_header: Header = Header.from_bytes(packet[Header.header_size:Header.header_size * 2])
            new_inner_header: Header = get_reverse_header(inner_header)
            new_inner_header.src_ip = self.self_ip
            new_inner_header.src_port = self.self_port
            new_inner_header.tll = TTL_MAX

            new_packet: bytes = new_outer_header.to_bytes() + new_inner_header.to_bytes() + packet[Header.header_size * 2:]
            self.__find_next_hop_and_forward__(new_packet)

    def __find_next_hop_and_forward__(self, packet: bytes):
        header = Header.from_bytes(packet[:Header.header_size])
        assert header.packet_type != 'L'

        next_hop = self.link_graph.find_next_hop(header)
        if next_hop is None:
            logging.fatal("INFO: Dropping packet, next hop not found %s", header)
            return
        header.ttl -= 1
        new_packet = header.to_bytes() + packet[Header.header_size:]
        self.sock.sendto(new_packet, (str(next_hop[0]), int(next_hop[1])))

    def __send_packet_to_client__(self, packet: bytes):
        header = Header.from_bytes(packet[:Header.header_size])
        assert header.wrapped
        assert header.dst_ip == self.self_ip and header.dst_port == self.self_port

        inner_header: Header = Header.from_bytes(packet[Header.header_size:Header.header_size * 2])
        assert not inner_header.wrapped
        inner_packet: bytes = packet[Header.header_size:]  # Only the inner packet is sent
        if (inner_header.dst_ip, inner_header.dst_port) in self.registered_clients:
            self.sock.sendto(inner_packet, (str(inner_header.dst_ip), int(inner_header.dst_port)))

    def __wrap_client_packet_and_send__(self, packet: bytes):
        header = Header.from_bytes(packet[:Header.header_size])
        assert not header.wrapped
        assert (header.src_ip, header.src_port) in self.registered_clients

        tunnel_header: TunnelHeader = TunnelHeader.from_bytes(packet[Header.header_size:Header.header_size + TunnelHeader.header_size])
        outer_header: Header = Header(self.self_ip, self.self_port, tunnel_header.dst_emulator_ip, tunnel_header.dst_emulator_port,
                                      header.packet_type, 0, header.ttl, header.payload_length, True)
        outer_packet: bytes = outer_header.to_bytes() + header.to_bytes() + packet[Header.header_size + TunnelHeader.header_size:]
        self.__find_next_hop_and_forward__(outer_packet)

    def forward_packet(self, packet: bytes):
        header = Header.from_bytes(packet[:Header.header_size])
        assert header.packet_type != 'L'
        assert not (header.src_ip == self.self_ip and header.src_port == self.self_port)

        if header.packet_type == 'A':
            assert header.dst_ip == self.self_ip and header.dst_port == self.self_port
            self.registered_clients.add((header.src_ip, header.src_port))
            return
        if header.packet_type in ['R', 'D', 'E', 'T']:
            if header.dst_ip == self.self_ip and header.dst_port == self.self_port:
                self.__send_packet_to_client__(packet)
                return
            if (header.src_ip, header.src_port) in self.registered_clients:
                self.__wrap_client_packet_and_send__(packet)
                return
        self.__find_next_hop_and_forward__(packet)


def handle_packets(self_port: int, topology_filename: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', self_port))
    sock.setblocking(False)

    self_ip = ipaddress.IPv4Address(socket.gethostbyname(socket.gethostname()))
    link_graph = LinkGraph(self_ip, self_port, topology_filename)
    link_maintenance = LinkMaintenance(link_graph, link_graph.link_state_map[(self_ip, self_port)].neighbour_list, sock, self_ip, self_port)

    while True:
        read_sockets, _, _ = select.select([sock], [], [], 0)
        if sock in read_sockets:
            packet = sock.recv(BUF_SIZE)
            header = Header.from_bytes(packet[:Header.header_size])
            if header.ttl == 0:
                link_maintenance.drop_packet(packet)
                continue

            if header.packet_type == 'L':
                link_maintenance.create_routes(packet)
            else:
                link_maintenance.forward_packet(packet)
        link_maintenance.send_pings()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='Emulator')
    parser.add_argument('-p', '--port', type=int, help='the port of the emulator', required=True)
    parser.add_argument('-f', '--filename', type=str, help='the name of the file containing the static forwarding table', required=True)

    args = parser.parse_args()
    Path("logs").mkdir(parents=True, exist_ok=True)
    logging.basicConfig(filename=f"logs/emu-{args.port}.log", level=logging.INFO, format='%(message)s', filemode='w')
    handle_packets(int(args.port), args.filename)
