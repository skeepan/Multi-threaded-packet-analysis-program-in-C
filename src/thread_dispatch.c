#include "thread_dispatch.h"

#include <pthread.h>
#include <signal.h>
#include <pcap.h>

#include "packet_parser.h"
#include "queue.h"
#include "hashmap.h"

#include "capture.h"
#define NUMTHREADS 5                              //Number of worker threads (feel free to change based on computer)

pthread_t tid[NUMTHREADS];                        //Array to store thread IDs

Queue *packet_Queue;                              //Queue for worker threads to handle packet data
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

pthread_mutex_t global_mutex = PTHREAD_MUTEX_INITIALIZER;
HashMap *unique_ip_HashMap;                       //Hashset to store SYN source ips 
volatile unsigned long SYN_count = 0;             //Global variables to return in intrusion detection report on program termination.
volatile unsigned long ARPrsp_count = 0;
volatile unsigned long urlcount_GOOGLE = 0;
volatile unsigned long urlcount_BBC = 0;

int THREAD_TERMINATION = 0;                       //Termination flag to be set in signalHandler.

// This function initializes the packet queue, unique IP HashMap, and creates worker threads.
// It is called in sniff.c
void init_threadq(void) {
  packet_Queue = create_queue();
  unique_ip_HashMap = initHashMap();
  int i;
  for(i=0;i<NUMTHREADS;i++){
		pthread_create(&tid[i],NULL,thread_func,NULL);
  }
  
}

// This function handles the termination signal (SIGINT) and prints the intrusion detection report.
void signalHandler (int sig) {
  printf("\nIntrusion Detection Report:\n"
        "%ld SYN packets detected from %ld IPs (syn attack)\n"
        "%ld ARP responses (cache poisoning)\n"
        "%ld URL Blacklist violations (%ld google and %ld bbc)\n",
        SYN_count, unique_ip_HashMap->size,
        ARPrsp_count,
        urlcount_BBC + urlcount_GOOGLE,
        urlcount_GOOGLE, urlcount_BBC);

  THREAD_TERMINATION++;                                         // Set the THREAD_TERMINATION flag to initiate the termination process. 
  pthread_cond_broadcast(&queue_cond);                          // Wake up all worker threads waiting on the queue condition variable. They will detect the THREAD_TERMINATION flag and terminate.
  
  int i = 0;
  for (i = 0; i<NUMTHREADS; i++) pthread_join(tid[i], NULL);
                                                                 
  pthread_mutex_lock(&queue_mutex);                             // Lock both mutexes for safe cleanup.
  pthread_mutex_lock(&global_mutex);

  freeQueue(packet_Queue);                                      // Freeing data structures.
  freeHashMap(unique_ip_HashMap);

  terminate_pcap();                                             // Freeing pcap associated memory.
  exit(sig);
}

// This function is the entry point for each thread created by the program.
// It processes packets from the packet queue, performs analysis, and stores the information
// in a StatParse struct defined in analysis.h. The thread then updates the global variables after a mutex lock.
void *thread_func (void *arg) {
  const unsigned char *packet;
  
  StatParse *parse = init_Parse();                              // Initialize a structure to store analysis results. The data in this struct is reset in analyse(), and the struct is freed upon program termination.

  while(!THREAD_TERMINATION){                                   // Main loop to process packets until THREAD_TERMINATION is set under signalHandler().
		pthread_mutex_lock(&queue_mutex);

		while(isEmpty(packet_Queue) && !THREAD_TERMINATION){  
			pthread_cond_wait(&queue_cond, &queue_mutex);
		}
    if (THREAD_TERMINATION) {                                   // Check if the thread should terminate.
      pthread_mutex_unlock(&queue_mutex);
      break;
    }
		packet = packet_Queue->head->packet;

		dequeue(packet_Queue);                                      // Dequeueing frees the queue element
		pthread_mutex_unlock(&queue_mutex);

    parse_packet(packet, parse);
    
    pthread_mutex_lock(&global_mutex);                          // Updating the global variables and hashing any relevant source IPs
    SYN_count += parse->SYN;
    ARPrsp_count += parse->ARPrsp;
    urlcount_GOOGLE += parse->GOOGLE;
    urlcount_BBC += parse-> BBC;
    if (parse->SYN) add(unique_ip_HashMap, parse->source_ip);
    pthread_mutex_unlock(&global_mutex);
    
  }
                                                                
  free(parse);                                                  // Once THREAD_TERMINATION is set, the StatParse struct is freed and the thread terminates its program.
  return NULL;
}

//This function enqueues packet header information into the packet_queue in a threadsafe manner.
void thread_dispatch(uint32_t len, const unsigned char *packet) { 
  pthread_mutex_lock(&queue_mutex);
	enqueue(packet_Queue, len, packet);
	pthread_cond_broadcast(&queue_cond);
	pthread_mutex_unlock(&queue_mutex);
}
