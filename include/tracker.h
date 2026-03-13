#pragma once

#include <windows.h>
#include <psapi.h>
#include <minwindef.h>
#include <cstddef>
#include <cstring>
#include <crtdbg.h>

#include "alloc_map.h"

#define no_mans_land_size 4

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


typedef struct CrtMemBlockHeader
{
// Pointer to the block allocated just before this one:
    CrtMemBlockHeader* _block_header_next;
// Pointer to the block allocated just after this one:
    CrtMemBlockHeader* _block_header_prev;
    char const*         _file_name;
    int                 _line_number;

    int                 _block_use;      // Type of block
    size_t              _data_size;      // Size of user block

    long                _request_number; // Allocation number
// Buffer just before (lower than) the user's memory:
    unsigned char       _gap[no_mans_land_size];

    // Followed by:
    // unsigned char    _data[_data_size];
    // unsigned char    _another_gap[no_mans_land_size];
} CrtMemBlockHeader;







