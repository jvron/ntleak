#pragma once
#include <minwindef.h>

#include "alloc_map.h"

enum LinkType {
    STATIC, STATIC_DEBUG, DYNAMIC, DYNAMIC_DEBUG, UNKOWN
};

class MemTracker{

public:

    size_t capacity;
    unsigned int allocCount;

    HashTable allocMap;
    void init();
    void trackAlloc(size_t size, void* ptr, AllocSource s);
    void trackFree(void* ptr);

    void resolveStackTrace(AllocRecord &record);
    bool isUserLeak(AllocRecord &record);
    void resolveSymbols();
    void report();

    void shutdown();

    bool trackingEnabled;
    bool trackFreeEnabled;
    LinkType linktype;

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








