#pragma once

#include <minwindef.h>
#include <cstddef>
#include <cstring>
#include <functional>

#define MAX_FRAMES 64
#define MAX_SYM_NAME 256
#define MAX_CAPACITY 10000

enum RecordStatus {

    EMPTY,
    USED,
    DELETED
};

struct AllocRecord{

    size_t size;
    void* address;
    bool active; //if the allocation is still active after end of user program - leak

    void* callStack[MAX_FRAMES]; //call stack is the logical sequence of funtion calls, while stack is a region in memory 
    
    USHORT frames; //unsigned short - 16bit / 2 byte int. Holds the number of stack frames

    char resolvedStack[MAX_FRAMES][MAX_SYM_NAME];

    //for hash table - checks if the slot is used
    
    RecordStatus status;

};


class HashTable {

public:

    static const int hashGroups = MAX_CAPACITY;
    //table is a pointer that points to the first element of an array of AllocRecord objects. points to the first element of the block of memory
    AllocRecord *table = nullptr;
    HashTable();
    ~HashTable();

    bool isEmpty();
    int hashFunction(void* ptr);
    void insertItem(void* ptr, AllocRecord &record);
    void deleteItem(void* ptr);
    AllocRecord* searchTable(void* ptr);

private:

    std::hash<void*> h;

};
