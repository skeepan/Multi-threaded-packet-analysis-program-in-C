#ifndef THREAD_DISPATCH_H
#define THREAD_DISPATCH_H

#include <pthread.h>
#include <signal.h>
#include <pcap.h>

#include "packet_parser.h"
#include "queue.h"
#include "hashmap.h"

extern int THREAD_TERMINATION;

void thread_dispatch(uint32_t len, const unsigned char *packet);
              
void init_threadq(void);

void *thread_func (void *arg);

void signalHandler (int sig);
#endif
