# Lab 3

## Directory structure
Example runs are provided.

- **Emulator:** Stores the trace and the emulator file. A sample topology file is also provided. `topology2.txt` contains the topology listed in the problem statement on local host, can be used for testing.
```shell
python3 trace.py -a 6000 -b 127.0.0.1 -c 1000 -d 127.0.0.1 -e 1000 -f 0
python3 emulator.py -p 4000 -f topology2.txt
```
- **Requester:** Contains the requester and the tracker file. Apart from standard options, requester should also be provided which emulator to connect. This emulator will route packets to and from the requester. The tracker file is also modified to include sender details along with emulators senders have connected to. Format: `<file-name> <id> <emulator-ip/port> <sender-ip/port>`. Multiple senders can connect to the same emulator as shown in the sample tracker file.
```shell
python3 requester.py -p 4001 -o split.txt -b 127.0.0.1 -c 4000
```
- **Sender:** The original sender code is in the sender folder and two sender folders contain a symlink to the original code. Apart from standard options, the sender should also be provided with the emulators to join.
```shell
python3 sender.py -p 5001 -g 4001 -r 1 -q 100 -l 100 -b 127.0.0.1 -c 5000
```

## Trace/Packet Route Logic

A primary problem both for the `trace` and `sender/receiver` is no emulators are aware of their location. Only the emulator that these applications connect to are aware of their presence (the topology doesn't record their presence). To solve this, tunnelling is used. Each application (`trace` or `sender/receiver`) registers itself to the concerned emulator. This makes the emulator aware that it has to server packet to/from this application. Within emulators, packets are routed via tunnelling. 

While sending a packet, the application attaches a `tunnel-header` which contains the destination emulator information. When the registered emulator (emulator serving the application), also referred as the source emulator, receives the packet, it reads and discards the `tunnel-header`, and forms an outer packet with the source and destination emulator address. After the destination emulator receives the packet, it unwraps the outer header and delivers only the inner packet to the application. 

`trace` is slightly special. When an emulator drops an `T`, it also modifies the inner header to include its own information. This is necessary since only the inner packet is delivered to the `trace` application. TTL is present for all packets and non `T` packets are silently dropped for expired TTLs. 

## Link-State Logic

To counter edge cases, each Link State message contains outgoing links from every emulator (discussed with the professor). So, if there are five emulators, link state messages will contain five records, each record containing the outgoing links from one emulator (similar to the topology file). Each record also contains a sequence number that is updated only when the corresponding emulator changes its set of outgoing links. This sequence number is used by emulators to identify stale records (updates forwarding table if necessary). There are no explicit Hello messages. If Link State messages are sent with same sequence number, they are not forwarded further and simply serve as Hello messages.