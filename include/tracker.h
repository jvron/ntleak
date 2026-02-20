#pragma once

#include <windows.h>
#include <psapi.h>
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

    void resolveStackTrace(AllocRecord &record);
    bool isUserLeak(AllocRecord &record);
    void resolveSymbols();
    void report();

    void shutdown();

    bool trackingEnabled;

private:

    bool symInit;
    HANDLE hProcess;

    HMODULE hExe;
    uintptr_t base;
    uintptr_t end;

};

//global tracker variable delaration 
//extern allows to share global varibles accross all translation units
extern MemTracker tracker; 







