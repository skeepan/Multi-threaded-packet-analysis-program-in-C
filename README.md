This program demonstrates a multi-threaded packet sniffing application that captures packets from a specified network interface using libpcap and libpthreads. The program utilizes a thread pool design to distribute packet analysis work among a fixed number of worker threads.

Program pipeline overview:
1. Packet Handling (main.c, sniff.c):
* The pcap_loop()function captures packets continuously, invoking the
dispatch() function for each packet, which enqueues the packet’s header in binary format to a FIFO work queue. This is performed under lock of the queue mutex. Once enqueued, the pthread_cond_broadcast()function is invoked
which wakes all sleeping threads.

2. Thread work and packet analysis (dispatch.c, analysis.c)
* Worker threads are responsible for packet analysis. They either wait for packets in the queue, or sleep until there is a packet in the queue, and then analyse the packet data using the analyse()function. After analysis, the thread updates global variables after obtaining a lock on the globals mutex.
* A StatParse struct in each thread tracks detected attacks and relevant information for each packet and is reset at the beginning of each analysis.
* A termination signal (SIGINT) triggers the termination process, signaling worker threads to complete their tasks and clean up resources.
  
3. Data Structures (queue.c, hashmap.c):
* Queue in queue.c implements a basic FIFO queue used to store packet
information for worker threads.
* HashMap in hashmap.c implements a simple hash set to store unique IP
addresses involved in SYN attacks.
