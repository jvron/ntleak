#pragma once

#include <minwindef.h>
#include <windows.h>
#include <cstddef>
#include <string>

#define MAX_FRAMES 64
#define MAX_SYM_NAME 256

struct AllocRecord{

    size_t size;
    void* address;
    bool active;

    void* callStack[MAX_FRAMES]; //call stack is the logical sequence of funtion calls, while stack is a region in memory 
    
    USHORT frames; //unsigned short - 16bit / 2 byte int. Holds the number of stack frames

    char resolvedStack[MAX_FRAMES][MAX_SYM_NAME];

};



class MemTracker{

public:

    size_t capacity;
    unsigned int count;

    AllocRecord *record = nullptr;
    void init();
    void trackAlloc(size_t size, void* ptr);
    void trackFree(void* ptr);

    void resolveSymbols(AllocRecord &record);
    void report();

    void shutdown();

private:

    bool symInit;
    HANDLE hProcess;

};

//global tracker variable delaration 
//extern allows to share global varibles accross all translation units
extern MemTracker tracker; 

void resolve(MemTracker &tracker);




