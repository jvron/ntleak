#pragma once

#include <cstddef>

struct AllocRecord{

    size_t size;
    void* address;
    bool active;
};


class MemTracker{

public:

    size_t capacity;
    unsigned int count;

    AllocRecord *record = nullptr;

    void init();
    void trackAlloc(size_t size, void* ptr);
    void trackFree(void* ptr);
    void report();

    void shutdown();

};

//global tracker variable delaration 
//extern allows to share global varibles accross all translation units
extern MemTracker tracker; 



