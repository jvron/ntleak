#include <MinHook.h>
#include <cstddef>
#include <cstdlib>
#include <heapapi.h>
#include <memoryapi.h>
#include <minwindef.h>
#include <stdio.h>
#include <winnt.h>

#include "hooks.h"
#include "tracker.h"

//function pointers that points to the original funtion. MinHook will store the target functions in these function pointers

void* (*pMallocOriginal)(size_t size) = NULL;
void (*pFreeOriginal)(void* ptr) = NULL;

void* (*pReallocOriginal)(void* memptr, size_t size) = NULL;

LPVOID (*pHeapAllocOriginal)(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes) = NULL;
BOOL (*pHeapFreeOriginal) (HANDLE hHeap, DWORD dwFlags, LPVOID lpMem) = NULL;

LPVOID (*pVirtualAllocOriginal) (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = NULL;
BOOL (*pVirtualFreeOriginal) (LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) = NULL; 


thread_local bool inMalloc = false;
thread_local bool inRealloc = false;


void* detourMalloc(size_t size)
{   
    inMalloc = true;

    void *memptr = pMallocOriginal(size);

    if (memptr != NULL)
    {
        tracker.trackAlloc(size, memptr);
    };

    //printf("malloc returned: %p\n", memptr);
    inMalloc = false;
    return memptr;

}

void detourFree(void *ptr)
{   
    pFreeOriginal(ptr);
    tracker.trackFree(ptr);

    //printf("free called at: %p\n", ptr);
}

void* detourRealloc(void *memptr, size_t size)
{   
    inRealloc = true;
    void* newptr = pReallocOriginal(memptr, size);

    if(newptr != NULL)
    {   
        if (newptr != memptr) // new pointer returned by realloc, old ptr freed
        {
            tracker.trackFree(memptr);
            tracker.trackAlloc(size, newptr);
        }
        else if (memptr == NULL) //same as malloc
        {
            tracker.trackAlloc(size, newptr);
        }
        else if (newptr == memptr)
        {
            tracker.trackAlloc(size, memptr); // replace the old allocation with new size
        }
    }

    if (newptr == NULL && size == 0)
    {
        // same as free
        tracker.trackFree(memptr);
    }

    //printf("realloc called at: %p\n", memptr);
    //printf("realloc returned: %p\n", newptr);
    inRealloc = false;
    return newptr;
}

LPVOID detourHeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
{
    void* memptr = pHeapAllocOriginal(hHeap, dwFlags, dwBytes);
    

    if (memptr != NULL && !inMalloc && !inRealloc) // do not track heapAlloc triggered by malloc and realloc
    {   
        tracker.trackAlloc(dwBytes, memptr);
        //printf("HeapAlloc tracked at: %p\n", hHeap);
    } 

    return memptr;
}

BOOL detourHeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
{
    BOOL result = pHeapFreeOriginal(hHeap, dwFlags, lpMem);

    if (result != 0)
    {
        tracker.trackFree(lpMem);
    }

    return result;
}

PVOID detourVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    void* memptr = pVirtualAllocOriginal(lpAddress, dwSize, flAllocationType, flProtect);
    if (memptr != NULL)
    {
        tracker.trackAlloc(dwSize, memptr);
    }

    return memptr;
}

BOOL detourVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    BOOL result = pVirtualFreeOriginal(lpAddress, dwSize, dwFreeType);

    if (result != 0)
    {
        tracker.trackFree(lpAddress);
    }

    return result;

}

MH_STATUS removeHooks()
{   
    MH_STATUS status;

    status = MH_DisableHook((void*)&malloc);
    if (status != MH_OK) return status;
    

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

    status = MH_DisableHook((void*)&realloc);
    if(status != MH_OK) return status;

    MH_RemoveHook((void*)&malloc);
    MH_RemoveHook((void*)&free);
    MH_RemoveHook((void*)&HeapAlloc);
    MH_RemoveHook((void*)&HeapFree);
    MH_RemoveHook((void*)&VirtualAlloc);
    MH_RemoveHook((void*)&VirtualFree);
    MH_RemoveHook((void*)&realloc);

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

MH_STATUS hookRealloc()
{
    MH_STATUS status;

    status = MH_CreateHook((void*)&realloc, (void*) &detourRealloc, reinterpret_cast<LPVOID*>(&pReallocOriginal));

    if(status != MH_OK)
    {
        return status;
    }

    status = MH_EnableHook((void*)&realloc);
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


MH_STATUS hookVirtualAlloc()
{
    MH_STATUS status;

    status = MH_CreateHook((void*)&VirtualAlloc, (void*) &detourVirtualAlloc, reinterpret_cast<LPVOID*>(&pVirtualAllocOriginal));

    if(status != MH_OK)
    {
        return status;
    }

    status = MH_EnableHook((void*)&VirtualAlloc);
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

MH_STATUS hookVirtualFree()
{
    MH_STATUS status;

    status = MH_CreateHook((void*)&VirtualFree, (void*) &detourVirtualFree, reinterpret_cast<LPVOID*>(&pVirtualFreeOriginal));

    if(status != MH_OK)
    {
        return status;
    }

    status = MH_EnableHook((void*)&VirtualFree);
  
    if (status != MH_OK)
    {
        return status;
    }
    
    return status;
}