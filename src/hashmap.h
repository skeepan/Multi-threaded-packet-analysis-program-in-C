#ifndef HASHMAP_H
#define HASHMAP_H

#include <stdio.h>
#include <netinet/ip.h>
#include <stdlib.h>

// Structure for a linked list node
typedef struct ListElement {
    uint32_t ip;
    struct ListElement* next;
} ListElement;

// Structure for a linked list
typedef struct LinkedList {
    ListElement* head;
} LinkedList;

// Structure for the HashMap
typedef struct HashMap {
    LinkedList* table;
    unsigned long size;
    unsigned long capacity;
    float LOAD_FACTOR;
} HashMap;

// Function declarations

// Function to initialize the HashMap
HashMap* initHashMap(void);

// Function to initialize a linked list
void initLinkedList(LinkedList* list);

// Function to add a key-value pair to the HashMap
void add(HashMap* map, uint32_t ip);

// Function to resize the HashMap
void resize(HashMap* map);

void freeList(HashMap* map);

void freeHashMap(HashMap* map); 
#endif  // HASHMAP_H
