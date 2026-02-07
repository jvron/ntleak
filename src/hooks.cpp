#include "hooks.h"
#include <MinHook.h>
#include <cstddef>
#include <stdio.h>

//function pointers that points to the original funtion. MinHook will store the target functions in these function pointers

void* (*pMallocOriginal)(size_t size) = NULL;
void* (*pFreeOriginal)(void* ptr) = NULL;


void* detourMalloc(size_t size)
{
    void *memptr = pMallocOriginal(size);

    if (memptr == NULL) return NULL;

    printf("malloc() hooked: %zu bytes allocated at %p\n", size, memptr);

    return memptr;
}

void detourFree(void *ptr)
{   
    printf("free() hooked: freed at %p\n", ptr);
    pFreeOriginal(ptr);
}

MH_STATUS hookMalloc()
{
    MH_STATUS status;

    status = MH_CreateHook((void*)&malloc, (void*) &detourMalloc, reinterpret_cast<LPVOID*>(&pMallocOriginal));

    if(status != MH_OK)
    {
        return status;
    }

    status = MH_EnableHook((void*)&malloc);
    if (status != MH_OK)
    {
        return status;
    }

    return status;
}

MH_STATUS hookFree()
{
    MH_STATUS status;

    status = MH_CreateHook((void*)&free, (void*) &detourFree, reinterpret_cast<LPVOID*>(&pFreeOriginal));

    if(status != MH_OK)
    {
        return status;
    }

    status = MH_EnableHook((void*)&free);
    if (status != MH_OK)
    {
        return status;
    }

    return status;
}