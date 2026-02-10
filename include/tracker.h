#pragma once

#include <windows.h>
#include <minwindef.h>
#include <cstddef>
#include <cstring>

#include "alloc_map.h"





class MemTracker{

public:

    size_t capacity;
    unsigned int allocCount;

    HashTable allocMap;
    void init();
    void trackAlloc(size_t size, void* ptr);
    void trackFree(void* ptr);

    void resolveSymbols();
    void report();

    void shutdown();

    bool trackingEnabled;

private:

    bool symInit;
    HANDLE hProcess;

};

//global tracker variable delaration 
//extern allows to share global varibles accross all translation units
extern MemTracker tracker; 






