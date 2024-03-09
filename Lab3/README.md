# Lab 3

**Project 3: Link State Routing**
---------------------------------

**Due: May 1, 2023**

**Overview**
------------

In this programming assignment, you will modify the emulators that you implemented in project 2, to perform a link-state routing protocol to determine the shortest paths between a fixed, known set of nodes in the lab. The paths between the nodes will be reconfigurable and new routes must stabilize within a fixed time period.

Your emulators will also forward packets from the _routetrace_ application that you will build to the node which is the next hop in the shortest path to a specified destination.

In this assignment, we will not provide you with each and every detail of how you should implement the link-state protocol. Instead, we will specify a set of requirements that your program should satisfy.

As with the first two programming assignments, you are to work in teams and write your code in python and submit your codes into Canvas.

**Project Details**
-------------------

Each node in the network is defined by an {IP,port} pair. After start-up, each emulator will implement the following functions: _readtopology_, _createroutes_, _forwardpacket, and buildForwardTable_ .

### **readtopology**

**_readtopology_** will read a text file (topology.txt) which defines the interconnection structure of a test network that can have up to 20 nodes. The topology structure will be stored in a file and will have the following format:

IP\_a,port\_w IP\_b,port\_x IP\_c,port\_y IP\_d,port\_z …  
IP\_b,port\_x IP\_a,port\_w IP\_c,port\_y IP\_d,port\_z …  
...

The first {IP,port} pair in each line of the topology file corresponds to a node which is running an emulator and will be listening for packets from all of the remaining IP,port pairs in the line (ie. a one-way connection to the first node from all of the other nodes). The pairs are separated by a whitespace character. You can assume that there will be bidirectional connections to and from each node in the topology and that the topology file will be set up to reflect this. A simple network has topology as follows:

![image](https://github.com/silversword05/CS640-Lab/assets/29013140/d4d53eba-204f-4803-9c27-815b2c5289be)


Imagine we have a network with above topology, and here are the IP addresses and ports for each node:

| Node | IP | Port |
|---|---|---|
| 1 | 1.0.0.0 | 1 |
| 2 | 2.0.0.0 | 2 |
| 3 | 3.0.0.0 | 3 |
| 4 | 4.0.0.0 | 4 |
| 5 | 5.0.0.0 | 5 |

The topology.txt will then look like:

1.0.0.0,1 2.0.0.0,2 3.0.0.0,3  
2.0.0.0,2 1.0.0.0,1 3.0.0.0,3 5.0.0.0,5  
3.0.0.0,3 1.0.0.0,1 2.0.0.0,2 4.0.0.0,4  
4.0.0.0,4 3.0.0.0,3 5.0.0.0,5  
5.0.0.0,5 2.0.0.0,2 4.0.0.0,4

The assumption after _readtopology_ is executed is that all nodes should be "alive" and that the process of setting up the routing table should begin. _readtopology_ only needs to be executed once when the emulator is started and the application can assume that the topology file (topology.txt) is in the same directory in which the emulator code is running. Note that this means that the emulator knows the whole topology at the startup. After that, the emulator will call _buildForwardTable_ (described below)  to calculate the shortest path to other nodes based on this topology. Note that the topology might be updated later when some nodes come up or go down.

### **createroutes**

**_createroutes_** will implement a link-state routing protocol to set up a shortest path forwarding table between nodes in the specified topology. Through this function, each emulator will maintain the **route topology** containing the interconnection structure of the whole network, and a **forwarding table** containing entries in the form of (Destination, Nexthop), where Nexthop is the next hop on the shortest path to the destination. The routing topology and the forwarding table must be updated if a node state change takes place. You should refer to the course textbook for details (from page 252 to 258)  on how the link-state protocol works and follow that protocol in your implementation.

The _createroutes_ function should run continuously after the topology has been specified by _readtopology_. It must be designed to react to nodes being responsive or unresponsive in the network and will require link-state information to be transmitted between an emulator and its neighbors.

The interval of transmission (ie. how frequently updates are sent) is up to you as is the mode of transport (TCP or UDP) and the link-state packet format. However you must ensure that your routing topology stabilizes within **5 seconds** after a node state change takes place (For example when emulator 3 is disconnected). For the purpose of the routing algorithm, you should assume that the distance between neighbor nodes is 1 ie. weights on each link between nodes is 1.

**Notes**

*   Note that you should implement the link-state protocol. Thus, you should implement the "reliable flooding" algorithm where each node communicates only with its neighbors. It is true that your emulator can figure out every node on the topology from the topology file but it is **NOT OK** to contact any node other than your neighbors directly in this implementation.
*   Note that your shortest path computations should be updated both when a node goes down, and when a node comes up.
*   Here are the messages you need to send and handle in this function:
    *   **HelloMessage**: At defined intervals, each emulator should send the HelloMessage to its immediate neighbors. The goal of this message is letting the node know the state of its immediate neighbors.  
        *   If a sufficiently long time passes without receipt of a “hello” from a neighbor, the link to that neighbor will be declared unavailable. In this case, you need to change the topology stored in this emulator, and generate a new LinkStateMessage to reflect this fact. 
        *   Similarly, when handling the helloMessage coming from an unavailable neighbor, you should declare it available, update the topology, and generate a new LinkStateMessage.
    *   **LinkStateMessage**: At defined intervals, each emulator should send a LinkStateMessage to its immediate neighbors. It contains the following information:  
        *   The (ip, port) pair of the node that created the message.
        *   A list of directly connected neighbors of that node, with the cost of the link to each one.
        *   A sequence number.
        *   A time to live for this packet.When handling a the LinkStateMessage from a neighbor, your code should:
    *   When handling a the LinkStateMessage from a neighbor, your code should:
        *   Update the topology stored in this emulator if necessary.  If the topology is changed, do the shortest path calculation again by calling the _buildForwardTable_ function.
        *   Call _forwardpacket_ function to make a process of flooding the LinkStateMessage to other nodes.

### **forwardpacket**

**_forwardpacket_** will determine whether to forward a packet and where to forward a packet received by an emulator in the network. Your emulator should be able to handle both packets regarding the link-state protocol (refer to the textbook), and packets that are forwarded to it from the _routetrace_ application (described below). The packet format of the link-state messages is up to you. 

### **buildForwardTable**

**buildForwardTable** will use the _forward search_ algorithm (see page 256-258 in the textbook) to compute a forwarding table based on the topology it collected from LinkStateMessage. The forwarding table contains entries in the form of (Destination, Nexthop). Anytime an emulator node detects a change of its topology, it should call the buildForwardTable function to update its forwarding table.

### **Emulator**

The emulator will be invoked as follows:

 **python3 emulator.py -p <port> -f <filename>**

*   **port:** the port that the emulator listens on for incoming packets.
*   **filename:** the name of the topology file described above.

Note that for each emulator, you are **required to print** the topology and forwarding table each time it’s changed. See the example section for more details. You might want to print some other debugging information from the emulator so that if your program is not behaving as expected at the demo time we can analyze what your program does and does not do correctly. 

**_routetrace_** **Details**
----------------------------

_routetrace_ is an application similar to the standard _traceroute_ tool which will trace the hops along a shortest path between the source and destination emulators. _routetrace_ will send packets to the source emulator with successively larger time-to-live values until the destination node is reached and will produce an output showing the shortest path to the destination. You will use this application to verify that your implementation of link-state protocol has the correct shortest paths between the nodes.

This application will generate an output that traces the shortest path between the source and destination node in the network that is given to it by the command line parameters below. An instance of _routetrace_ will be invoked as follows:

**python3 trace.py -a <routetrace port> -b < source hostname> -c <source port> -d <destination hostname> -e <destination port> -f <debug option>**

*   **routetrace port:** the port that the _routetrace_ listens on for incoming packets.
*   **source hostname, source port, destination hostname, destination port:** _routetrace_ will output the shortest path between the <source hostname, source port> to <destination hostname, destination port> .
*   **Debug option:** When the debug option is 1, the application will print out the following information about the packets that it sends and receives: TTL of the packet and the src. and dst. IP and port numbers. It will not do so when this option is 0.

This is the suggested packet format for the _routetrace_ application:

More concretely here is what the _routetrace_ application does:

1.  It gets the source and destination IP and port from the command line.
2.  It sets the TTL to 0
3.  Send a routetrace packet to the source with packet fields: "T", TTL, routetrace IP, routetrace Port, Destination IP, Destination Port
4.  Wait for a response.
5.  Once it gets a response, print out the responders IP and port (that it gets from the response packet).
6.  If the source IP and port fields of the routetrace packet that it received equals the destination IP and port that it received from the command line then TERMINATES.
7.  Otherwise, TTL = TTL + 1, goto 3.

Here is what your emulator should do once it receives a routetrace packet:

*   If TTL is 0, create a routetrace packet or modify the received routetrace packet. Put its own IP and Port to the source IP and port fields of the routetrace packet. Other fields of the packet should be identical to the packet it received. Send that back to the routetrace (using the source IP and port fields of the routetrace packet that it received)
*   If TTL is not 0, decrement the TTL field in the packet. Search in its route table and send the altered packet to the next hop on the shortest path to the destination.

**Example**
-----------

The Ctrl+ C command on the terminal will be used to temporarily disable an emulator in the topology. The idea is that the topology must be reconfigurable on the fly. When an emulator is disabled, it will cease forwarding packets and cease sending its routing messages to its neighbors. When the emulator is started again, it will begin participating in routing and forwarding again and the shortest path routes will get updated.

Sample test case:

Firstly, we start 5 emulators using topology.txt. In [topology.txt Links to an external site.](https://github.com/Tingjia980311/cs640/blob/main/topology.txt), we define a network looks like:

![image](https://github.com/silversword05/CS640-Lab/assets/29013140/0dfc2907-fd9a-4a5c-b9b9-c080b845d7c7)


We’ll give a sample output for the emulator with port 1 here. Other emulators have similar outputs. After the readtopology, it will print out the initial routing topology and forwarding table it gets from topology.txt:

**Topology:** 

**1.0.0.0,1 2.0.0.0,2 3.0.0.0,3  
2.0.0.0,2 1.0.0.0,1 3.0.0.0,3 5.0.0.0,5  
3.0.0.0,3 1.0.0.0,1 2.0.0.0,2 4.0.0.0,4  
4.0.0.0,4 3.0.0.0,3 5.0.0.0,5  
5.0.0.0,5 2.0.0.0,2 4.0.0.0,4**

**Forwarding table:**

**2.0.0.0,2 2.0.0.0,2  
3.0.0.0,3 3.0.0.0,3  
4.0.0.0,4 3.0.0.0,3  
5.0.0.0,5 2.0.0.0,2**

Consider the above topology. If we run the _routetrace_ application between nodes 1 and 4, here is the output that the routetrace application should get:

| Hop# | IP | Port |
|---|---|---|
| 1 | 1.0.0.0 | 1 |
| 2 | 3.0.0.0 | 3 |
| 3 | 4.0.0.0 | 4 |

Now let's disable emulator 3 by using the command Ctrl + C. Your routes should reconfigure. Within at most 5 seconds, the emulator with port 1 will print out the new topology and forwarding table:

**Topology:** 

**1.0.0.0,1 2.0.0.0,2  
2.0.0.0,2 1.0.0.0,1 5.0.0.0,5  
4.0.0.0,4 5.0.0.0,5  
5.0.0.0,5 2.0.0.0,2 4.0.0.0,4**

**Forwarding table:**

**2.0.0.0,2 2.0.0.0,2  
4.0.0.0,4 2.0.0.0,2  
5.0.0.0,5 2.0.0.0,2**

Once we run the _routetrace_ application again after a few seconds, we should get:

| Hop# | IP | Port |
|---|---|---|
| 1 | 1.0.0.0 | 1 |
| 2 | 3.0.0.0 | 3 |
| 3 | 5.0.0.0 | 5 |
| 4 | 4.0.0.0 | 4 |

Your program will be tested similarly with another topology at the demo time.

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
