#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

typedef struct element {
  struct element *next;
  const unsigned char *packet;
} Element;

typedef struct queue {
  struct element *head;
  struct element *tail;
} Queue;

Queue* create_queue(void){ //Creates a queue and returns its pointer
  Queue *q = (Queue *)malloc(sizeof(Queue));
  q->head=NULL;
  q->tail=NULL;
  return(q);
}

int isEmpty(Queue *q){
    return(q->head==NULL);
}

void enqueue(Queue *q, u_int32_t len, const unsigned char *packet) {
  Element *new_elem = (Element *)malloc(sizeof(Element));
  
  new_elem->packet = packet;
  new_elem->next = NULL; 

  if(isEmpty(q)){ 
    q->head=new_elem;
    q->tail=new_elem;
  }
  else{ //insert at the tail
    q->tail->next = new_elem;
    q->tail = new_elem;
  }

}

void dequeue(Queue *q) {
  Element *head_elem;
  if(isEmpty(q)){
    printf("Error: attempt to dequeue from an empty queue");
  }
  else{
    head_elem = q->head;
    q->head = head_elem->next;
    if(q->head==NULL)
      q->tail=NULL;
    free(head_elem);
    
  }
}

void freeQueue(Queue *q) {
  while (!isEmpty(q)) {
    dequeue(q);
  }
  free(q);
}