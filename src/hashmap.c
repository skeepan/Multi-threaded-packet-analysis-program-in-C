 
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

// Function to initialize a linked list
void initLinkedList(LinkedList* list) {
    list->head = NULL;
}

// Function to initialize the HashMap
HashMap* initHashMap(void) {
    struct HashMap *map = (HashMap *)malloc(sizeof(HashMap));
    map->capacity = 113;
    map->table = (LinkedList *)malloc(map->capacity * sizeof(LinkedList));
    map->size = 0;
    map->LOAD_FACTOR = 0.75f;
    // initialise all values to NULL
    int i;
    for (i = 0; i < map->capacity; i++) {
        initLinkedList(&(map->table[i]));
    }
    return(map);
}

ListElement* createListElement(uint32_t ip) {
    ListElement* new_Element = (ListElement*)malloc(sizeof(ListElement));
    new_Element->ip = ip;
    new_Element->next = NULL;
    return new_Element;
}

void addToLinkedList(LinkedList* list, ListElement* newElement) {
    newElement->next = list->head;
    list->head = newElement;
}

ListElement* findInLinkedList(LinkedList* list, uint32_t targetIp) {
    ListElement* current = list->head;

    while (current != NULL) {
        if (current->ip == targetIp) {
            // Found the target IP, return the ListElement
            return current;
        }
        current = current->next;
    }
    // IP not found in the linked list
    return NULL;
}

// Function to compute the hash code for a key
unsigned int hash(uint32_t x) {
    // Assuming key is an integer
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = (x >> 16) ^ x;
    return x;
}

// Function to resize the HashMap
void resize(HashMap* map) {
    // Create a new table with double the capacity
    LinkedList* newTable = (LinkedList*)malloc((((map->capacity)*2)+1)* sizeof(LinkedList));
    // Update the capacity
    int i;
    for (i = 0; i < ((map->capacity)*2)+1; i++) {
        initLinkedList(&(newTable[i]));
    }
    // Copy the old table to the new table
    for (int i = 0; i < map->capacity; i++) {
        ListElement* current = map->table[i].head;
        while (current != NULL) {
            ListElement* nextElement = current->next;
            // Copy each element to the new table
            int newI = hash(current->ip) % ((map->capacity)*2)+1;
            if (newI < 0) {
               newI = newI + ((map->capacity)*2)+1;
            }
            addToLinkedList(&newTable[newI], current);
            current = nextElement;
        }
    }

    // Free the old table
    free(map->table);

    // Set the table reference to the new table
    map->table = newTable;

    //Set the capacity of the new table
    map->capacity = ((map->capacity)*2)+1;
}

// Function to add a key-value pair to the HashMap
void add(HashMap* map, uint32_t ip) {
    // Check if the size exceeds the load factor threshold and resize the table if necessary
    if (map->size > map->LOAD_FACTOR * map->capacity) {
        resize(map);
    }
    
    // Compute the hash code and table location for the key
    int hash_code = hash(ip);
    int i = hash_code % map->capacity;

    // Handle negative locations by wrapping them around to the end of the table
    if (i < 0) {
        i = i + map->capacity;
    }

    //If this IP is not already stored in this location, add it to the linked list.
    if (findInLinkedList(&map->table[i], ip) == NULL) {
        ListElement* new_Element = createListElement(ip);

        addToLinkedList(&map->table[i], new_Element);
        // Increment the size of the table
        map->size++;
    }
}

void freeList(ListElement* head) {
    ListElement* current = head;
    while (current != NULL) {
        ListElement* next = current->next;
        free(current);
        current = next;
    }
}

void freeHashMap(HashMap* map) {
    // Free each linked list in the table
    for (int i = 0; i < map->capacity; i++) {
        freeList(map->table[i].head);
    }

    // Free the table itself
    free(map->table);

    // Free the HashMap structure
    free(map);
}





