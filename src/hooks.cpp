#include <MinHook.h>
#include <cstddef>
#include <heapapi.h>
#include <minwindef.h>
#include <stdio.h>
#include <winnt.h>

#include "hooks.h"
#include "tracker.h"

//function pointers that points to the original funtion. MinHook will store the target functions in these function pointers

void* (*pMallocOriginal)(size_t size) = NULL;
void* (*pFreeOriginal)(void* ptr) = NULL;
LPVOID (*pHeapAllocOriginal)(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes) = NULL;
BOOL (*pHeapFreeOriginal) (HANDLE hHeap, DWORD dwFlags, LPVOID lpMem) = NULL;


void* detourMalloc(size_t size)
{
    void *memptr = pMallocOriginal(size);

    if (memptr == NULL) return NULL;

    //printf("malloc() hooked: %zu bytes allocated at %p\n", size, memptr);

    tracker.trackAlloc(size, memptr);

    return memptr;
}

void detourFree(void *ptr)
{   
    //printf("free() hooked: freed at %p\n", ptr);
    tracker.trackFree(ptr);
    pFreeOriginal(ptr);
}

LPVOID detourHeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
{
    void* memptr = pHeapAllocOriginal(hHeap, dwFlags, dwBytes);

    if (memptr != NULL)
    {
        tracker.trackAlloc(dwBytes, memptr);
    } 

    return memptr;
}

BOOL detourHeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
{
    BOOL result = pHeapFreeOriginal(hHeap, dwFlags, lpMem);

    tracker.trackFree(lpMem);

    return result;
}

MH_STATUS disableHooks()
{   
    MH_STATUS status;
    status = MH_DisableHook((void*)&malloc);
    if (status != MH_OK)
    {
        return status;
    }

    status = MH_DisableHook((void*)&free);
    if (status != MH_OK)
    {
        return status;
    }

    status = MH_DisableHook((void*)&HeapAlloc);
    if (status != MH_OK)
    {
        return status;
    }

    status = MH_DisableHook((void*)&HeapFree);
    if (status != MH_OK) return status;

    return status;
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

MH_STATUS hookHeapAlloc()
{
    MH_STATUS status;

    status = MH_CreateHook((void*)&HeapAlloc, (void*) &detourHeapAlloc, reinterpret_cast<LPVOID*>(&pHeapAllocOriginal));

    if(status != MH_OK)
    {
        return status;
    }

    status = MH_EnableHook((void*)&HeapAlloc);
    if (status != MH_OK)
    {
        return status;
    }

    return status;
}

MH_STATUS hookHeapFree()
{
    MH_STATUS status;

    status = MH_CreateHook((void*)&HeapFree, (void*) &detourHeapFree, reinterpret_cast<LPVOID*>(&pHeapFreeOriginal));

    if(status != MH_OK)
    {
        return status;
    }

    status = MH_EnableHook((void*)&HeapFree);
    if (status != MH_OK)
    {
        return status;
    }

    return status;
}