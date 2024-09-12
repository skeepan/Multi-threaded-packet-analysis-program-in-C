#ifndef QUEUE_H
#define QUEUE_H

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

typedef struct element {
  struct element *next;
  //struct pcap_pkthdr *header;
  const unsigned char *packet;
} Element;

typedef struct queue {
  Element *head;
  Element *tail;
  int size;
} Queue;

Queue* create_queue(void);

int isEmpty(Queue *q);

void enqueue(Queue *q, uint32_t len, const unsigned char *packet);

void dequeue(Queue *q);  

void freeQueue(Queue *q);

#endif

