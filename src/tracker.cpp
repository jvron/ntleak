#include <windows.h>
#include <cstddef>
#include <libloaderapi.h>
#include <memoryapi.h>
#include <minwindef.h>
#include <winnt.h>
#include <iostream>

#include "tracker.h"


MemTracker tracker;

void MemTracker::init()
{   
    capacity = 10000;
    count = 0;

    record = (AllocRecord*) VirtualAlloc(NULL, capacity * sizeof(AllocRecord), MEM_COMMIT, PAGE_READWRITE);

    if (record == NULL)
    {
        record = nullptr;
        std::cout << "tracker init allocation failed\n";
    }

}


void MemTracker::trackAlloc(size_t size, void* ptr)
{
    record[count] = {size, ptr, true};
    count++;   
}

void MemTracker::trackFree(void *ptr)
{
    for (int i = 0; i < count; i++)
    {
        if(record[i].address == ptr)
        {
            record[i].active = false;
        }
    }
}

void MemTracker::report()
{
    for (int i = 0; i < count; i++)
    {
        std::cout << i << ": " << record[i].size << " bytes allocated at: " << record[i].address << "\n";

        if (!record[i].active)
        {
            std::cout << "allocated memory at: "<< record[i].address << " WAS freed\n";
        }
        else  {
            std::cout << "allocated memory WAS NOT freed\n";
        }
    }
}

void MemTracker::shutdown()
{
    BOOL result = VirtualFree(record, 0, MEM_RELEASE);
    
    if (result == 0)
    {
        std::cout << "virtualFree failed\n";
        return;
    }

    record = nullptr;
}